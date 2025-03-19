import os
import shutil
from collections import defaultdict
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import webbrowser
import requests

ETHERSCAN_API_KEY = "848HZHG8QKCE4DIMBV7P13CDSUARHXDX4T"
BASE_URL = "https://api.etherscan.io/api"

class spider_map:
    def fetch_transactions(wallet_address):
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': wallet_address,
            'startblock': 0,
            'endblock': 99999999,
            'sort': 'asc',
            'apikey': ETHERSCAN_API_KEY
        }
        
        response = requests.get(BASE_URL, params=params)
        return response.json()['result']

    def process_transactions(transactions, wallet_address):
        interaction_freq = defaultdict(lambda: {'in_frequency': 0, 'out_frequency': 0, 
                                            'total_eth_received': 0, 'total_eth_sent': 0})
        
        transaction_records = []
        
        for tx in transactions:
            timestamp = datetime.fromtimestamp(int(tx['timeStamp']))
            eth_value = float(tx['value']) / 1e18  # Convert from Wei to ETH
            
            if tx['from'].lower() == wallet_address.lower():
                # Sent transaction
                counter_party = tx['to']
                interaction_freq[counter_party]['out_frequency'] += 1
                interaction_freq[counter_party]['total_eth_sent'] += eth_value
                tx_type = 'sent'
            else:
                # Received transaction
                counter_party = tx['from']
                interaction_freq[counter_party]['in_frequency'] += 1
                interaction_freq[counter_party]['total_eth_received'] += eth_value
                tx_type = 'received'
                
            transaction_records.append({
                'counter_party': counter_party,
                'timestamp': timestamp,
                'type': tx_type,
                'eth_value': eth_value,
                'in_frequency': interaction_freq[counter_party]['in_frequency'],
                'out_frequency': interaction_freq[counter_party]['out_frequency'],
                'total_eth_received': interaction_freq[counter_party]['total_eth_received'],
                'total_eth_sent': interaction_freq[counter_party]['total_eth_sent']
            })
        
        return transaction_records

    def save_to_csv(transaction_records, wallet_address):
        df = pd.DataFrame(transaction_records)
        df.to_csv(f'analysis\\spider_map\\raw_transaction_data.csv', index=False)

    def filter_by_date_range(start_date, end_date):
        # Read the original CSV file
        try:
            df = pd.read_csv('analysis\\spider_map\\raw_transaction_data.csv')
            # Convert timestamp string back to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        except FileNotFoundError:
            print("Error: raw_transaction_data.csv not found!")
            return
        
        # Get date range from user
        while True:
            try:
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                
                if start_datetime > end_datetime:
                    print("Start date must be before end date!")
                    continue
                break
            except ValueError:
                print("Invalid date format! Please use YYYY-MM-DD")
        
        # Filter transactions within date range
        mask = (df['timestamp'].dt.date >= start_datetime.date()) & \
            (df['timestamp'].dt.date <= end_datetime.date())
        filtered_df = df[mask]
        
        # Group by counter_party to maintain frequency counts
        summary_df = filtered_df.groupby('counter_party').agg({
            'timestamp': 'first',  # Keep the first timestamp
            'in_frequency': 'max',  # Keep the max frequency counts
            'out_frequency': 'max',
            'total_eth_received': 'max',
            'total_eth_sent': 'max'
        }).reset_index()
        
        # Save filtered data
        summary_df.to_csv('analysis\\spider_map\\filtered_transaction_data.csv', index=False)
        print(f"\nFiltered transactions saved to 'filtered_transaction_data.csv'")
        print(f"Found {len(summary_df)} unique addresses in the date range")
        return summary_df

    def create_3d_spider_map(batch_df, main_wallet, batch_number):
        # Ensure html_files directory exists
        html_dir = "analysis\\spider_map\\html_files"
        if not os.path.exists(html_dir):
            os.makedirs(html_dir)
        
        # Clean up any old batch files with the same number to prevent conflicts
        old_file = os.path.join(html_dir, f"3d_spider_map_batch_{batch_number}.html")
        if os.path.exists(old_file):
            os.remove(old_file)
        
        G = nx.DiGraph()
        
        # Add nodes and edges
        for _, row in batch_df.iterrows():
            counter_party = row['counter_party']
            
            G.add_node(main_wallet, type='main')
            G.add_node(counter_party, type='counter_party')

            if row['in_frequency'] > 0:
                G.add_edge(counter_party, main_wallet, 
                        weight=row['in_frequency'],
                        color='blue',
                        eth_amount=row['total_eth_received'])
            
            if row['out_frequency'] > 0:
                G.add_edge(main_wallet, counter_party, 
                        weight=row['out_frequency'],
                        color='red',
                        eth_amount=row['total_eth_sent'])

        # Calculate 3D layout
        pos_3d = nx.spring_layout(G, dim=3, seed=42)
        
        # Create edge traces
        edge_traces = []
        for edge in G.edges():
            x0, y0, z0 = pos_3d[edge[0]]
            x1, y1, z1 = pos_3d[edge[1]]
            edge_width = G.edges[edge]['weight'] * 0.5
            
            edge_trace = go.Scatter3d(
                x=[x0, x1], y=[y0, y1], z=[z0, z1],
                line=dict(width=edge_width, color=G.edges[edge]['color']),
                hoverinfo='none',
                mode='lines'
            )
            edge_traces.append(edge_trace)

        # Create node trace
        node_x, node_y, node_z = [], [], []
        node_colors, node_sizes = [], []
        hover_texts, node_texts = [], []
        
        for node in G.nodes():
            x, y, z = pos_3d[node]
            node_x.append(x)
            node_y.append(y)
            node_z.append(z)
            
            if node == main_wallet:
                node_colors.append('yellow')
                node_sizes.append(15)
                hover_text = f"Main Wallet: {node[:10]}..."
            else:
                node_colors.append('lightblue')
                node_sizes.append(10)
                
                in_edges = list(G.in_edges(node))
                out_edges = list(G.out_edges(node))
                
                in_freq = sum([G.edges[edge]['weight'] for edge in in_edges]) if in_edges else 0
                out_freq = sum([G.edges[edge]['weight'] for edge in out_edges]) if out_edges else 0
                eth_received = sum([G.edges[edge]['eth_amount'] for edge in in_edges]) if in_edges else 0
                eth_sent = sum([G.edges[edge]['eth_amount'] for edge in out_edges]) if out_edges else 0
                
                hover_text = f"Address: {node[:10]}...<br>" + \
                            f"Sent Frequency: {out_freq}<br>" + \
                            f"Received Frequency: {in_freq}<br>" + \
                            f"ETH Sent: {eth_sent:.4f}<br>" + \
                            f"ETH Received: {eth_received:.4f}"
            
            hover_texts.append(hover_text)
            node_texts.append(node[:6] + "...")
        
        node_trace = go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            text=node_texts,
            mode='markers+text',
            hovertext=hover_texts,
            hoverinfo='text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                opacity=0.8,
                line=dict(width=1, color='black')
            ),
            textposition="bottom center"
        )
        
        # Create 3D figure with interactive features
        fig = go.Figure(
            data=[*edge_traces, node_trace],
            layout=go.Layout(
                title=f"3D Ethereum Transaction Spider Map - Batch {batch_number}",
                showlegend=False,
                scene=dict(
                    xaxis=dict(title='', showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(title='', showgrid=False, zeroline=False, showticklabels=False),
                    zaxis=dict(title='', showgrid=False, zeroline=False, showticklabels=False),
                    camera=dict(eye=dict(x=1.5, y=1.5, z=1.5)),
                    dragmode='orbit',
                    aspectmode='data'
                ),
                margin=dict(l=0, r=0, b=0, t=30),
                hovermode='closest'
            )
        )

        output_file = os.path.join(html_dir, f"3d_spider_map_batch_{batch_number}.html")
        fig.write_html(output_file)
        print(f"3D Spider map has been created as '{output_file}'")

    def main(wallet_address, start_date, end_date):
        #wallet_address = input("Enter the Ethereum wallet address: ") or "0x1ab4973a48dc892cd9971ece8e01dcc7688f8f23"
        #print("Fetching transactions...")
        transactions = spider_map.fetch_transactions(wallet_address)
        
        if not transactions:
            #print("No transactions found or error occurred!")
            return
        
        #print("Processing transactions...")
        transaction_records = spider_map.process_transactions(transactions, wallet_address)
        
        #print("Saving to CSV file...")
        spider_map.save_to_csv(transaction_records, wallet_address)
        
        #print(f"Done! File 'raw_transaction_data.csv' has been created successfully.")
        
        filtered_df = spider_map.filter_by_date_range(start_date, end_date)
        if filtered_df is None:
            return
        
        main_wallet = wallet_address.lower()
        
        # Clean up any previous html_files contents first
        html_dir = "analysis\\spider_map\\html_files"
        if os.path.exists(html_dir):
            # Delete all existing batch files
            for file in os.listdir(html_dir):
                if file.startswith("3d_spider_map_batch_"):
                    os.remove(os.path.join(html_dir, file))
        else:
            os.makedirs(html_dir)
        
        total_batches = (len(filtered_df) // 200) + 1
        for batch_number in range(total_batches):
            batch_df = filtered_df.iloc[batch_number*200:(batch_number+1)*200]
            spider_map.create_3d_spider_map(batch_df, main_wallet, batch_number + 1)
        
        # Updated import and file handling
        try:
            # Get the current script's directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            combine_path = os.path.join(current_dir, "combine.py")
            
            if os.path.exists(combine_path):
                import sys
                sys.path.append(current_dir)
                import combine
                combine.create_master_html()
                master_path = os.path.join(current_dir, "master.html")
                webbrowser.open(master_path)
            else:
                print(f"combine.py not found in {current_dir}")
                print("Please ensure combine.py is in the same directory as fetch_and_store.py")
        except Exception as e:
            print(f"Error loading combine.py: {str(e)}")

#spider_map.main("0x1ab4973a48dc892cd9971ece8e01dcc7688f8f23","2024-01-11","2024-01-12")