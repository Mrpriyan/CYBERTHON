import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
from io import BytesIO
import base64
import os
from datetime import datetime
import numpy as np

def generate_transaction_spidermap(df, wallet_address, max_nodes=50, min_transaction_value=0.1):
    """
    Generate a spidermap visualization of Ethereum transactions.
    
    Args:
        df (DataFrame): DataFrame containing transaction data
        wallet_address (str): The central wallet address to analyze
        max_nodes (int): Maximum number of nodes to display
        min_transaction_value (float): Minimum ETH value to include in visualization
    
    Returns:
        str: Base64 encoded PNG image of the spidermap
    """
    # Normalize wallet address format
    wallet_address = wallet_address.lower()
    
    # Filter transactions by minimum value
    filtered_df = df[df['eth_value'] >= min_transaction_value].copy()
    
    # Create a directed graph
    G = nx.DiGraph()
    
    # Add the main wallet as the central node
    G.add_node(wallet_address, size=1500, color='red', type='main')
    
    # Dictionary to track total transaction value per address
    address_values = {}
    
    # Process each transaction
    for _, row in filtered_df.iterrows():
        from_addr = row['from'].lower()
        to_addr = row['to'].lower()
        value = float(row['eth_value'])
        
        # Skip if either address is None or empty
        if not from_addr or not to_addr:
            continue
            
        # Add nodes if they don't exist
        if from_addr != wallet_address and from_addr not in G:
            G.add_node(from_addr, size=300, color='blue', type='external')
            address_values[from_addr] = 0
            
        if to_addr != wallet_address and to_addr not in G:
            G.add_node(to_addr, size=300, color='green', type='external')
            address_values[to_addr] = 0
        
        # Track total value per address
        if from_addr != wallet_address:
            address_values[from_addr] = address_values.get(from_addr, 0) + value
        if to_addr != wallet_address:
            address_values[to_addr] = address_values.get(to_addr, 0) + value
        
        # Add or update edge
        if G.has_edge(from_addr, to_addr):
            G[from_addr][to_addr]['weight'] += value
            G[from_addr][to_addr]['count'] += 1
        else:
            G.add_edge(from_addr, to_addr, weight=value, count=1)
    
    # Limit to top nodes by transaction value
    if len(G.nodes) > max_nodes + 1:  # +1 for the main address
        # Sort addresses by value (excluding main address)
        sorted_addresses = sorted(
            [(addr, val) for addr, val in address_values.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        # Keep only the top addresses
        top_addresses = set([addr for addr, _ in sorted_addresses[:max_nodes]])
        top_addresses.add(wallet_address)  # Always keep the main address
        
        # Remove nodes not in top addresses
        nodes_to_remove = [node for node in G.nodes if node not in top_addresses]
        G.remove_nodes_from(nodes_to_remove)
    
    # Prepare for visualization
    fig, ax = plt.figure(figsize=(14, 14), dpi=100), plt.gca()
    
    # Use spring layout for better visualization of connected components
    pos = nx.spring_layout(G, k=0.3, iterations=50)
    
    # Extract node attributes for drawing
    node_sizes = [G.nodes[node].get('size', 300) for node in G.nodes()]
    node_colors = [G.nodes[node].get('color', 'blue') for node in G.nodes()]
    
    # Calculate edge widths based on transaction values
    edge_weights = [G[u][v]['weight'] for u, v in G.edges()]
    max_weight = max(edge_weights) if edge_weights else 1
    edge_widths = [1 + (5 * w / max_weight) for w in edge_weights]
    
    # Draw the network
    nodes = nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8, ax=ax)
    edges = nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True, 
                                   arrowstyle='->', arrowsize=15, ax=ax)
    
    # Draw labels for the main wallet and top 10 interacting addresses
    if len(G.nodes) <= 20:
        # Draw all labels if we have 20 or fewer nodes
        nx.draw_networkx_labels(G, pos, font_size=10, ax=ax)
    else:
        # Otherwise, just label the main address and a few top addresses
        top_by_edge_weight = sorted(
            [(node, sum(G[u][v]['weight'] for u, v in G.edges() if u == node or v == node)) 
             for node in G.nodes if node != wallet_address],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_addresses = set([addr for addr, _ in top_by_edge_weight])
        top_addresses.add(wallet_address)
        labels = {node: node[:10] + '...' for node in top_addresses}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=10, ax=ax)

    # Add title and legend
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    plt.title(f"Transaction Spidermap for {wallet_address[:10]}...\n(Generated on {timestamp})")
    
    # Create custom legend
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=15, label='Main Wallet'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Sending Address'),
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Receiving Address'),
        plt.Line2D([0], [0], color='gray', lw=2, label='Transaction Flow')
    ]
    ax.legend(handles=legend_elements, loc='lower right')
    
    # Add some stats
    stats_text = (
        f"Total Transactions: {len(filtered_df)}\n"
        f"Unique Addresses: {len(G.nodes)-1}\n"  # Subtract 1 for main address
        f"Min ETH Value: {min_transaction_value}"
    )
    plt.figtext(0.02, 0.02, stats_text, fontsize=12, bbox=dict(facecolor='white', alpha=0.7))
    
    # Remove axes
    plt.axis('off')
    
    # Save to BytesIO buffer
    buffer = BytesIO()
    plt.tight_layout()
    plt.savefig(buffer, format='png', dpi=100)
    buffer.seek(0)
    plt.close()
    
    # Convert to base64 for easy embedding in HTML
    image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return image_base64

def save_spidermap_to_file(df, wallet_address, output_dir, filename=None, **kwargs):
    """
    Generate a spidermap and save it to a file.
    
    Args:
        df (DataFrame): DataFrame containing transaction data
        wallet_address (str): The central wallet address to analyze
        output_dir (str): Directory to save the image
        filename (str, optional): Filename to use. Defaults to wallet_address_spidermap.png
        **kwargs: Additional arguments to pass to generate_transaction_spidermap
    
    Returns:
        str: Path to the saved file
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate default filename if not provided
    if not filename:
        filename = f"{wallet_address[:10]}_spidermap.png"
    
    # Generate the spidermap image
    image_base64 = generate_transaction_spidermap(df, wallet_address, **kwargs)
    
    # Decode and save to file
    image_data = base64.b64decode(image_base64)
    file_path = os.path.join(output_dir, filename)
    
    with open(file_path, 'wb') as f:
        f.write(image_data)
    
    return file_path

def get_transaction_stats(df, wallet_address):
    """
    Generate statistics about the transactions.
    
    Args:
        df (DataFrame): DataFrame containing transaction data
        wallet_address (str): The wallet address to analyze
    
    Returns:
        dict: Statistics about the transactions
    """
    wallet_address = wallet_address.lower()
    
    # Split into sent and received
    sent = df[df['from'].str.lower() == wallet_address]
    received = df[df['to'].str.lower() == wallet_address]
    
    # Get unique addresses
    unique_senders = received['from'].str.lower().nunique()
    unique_receivers = sent['to'].str.lower().nunique()
    
    # Calculate values
    total_sent = sent['eth_value'].sum()
    total_received = received['eth_value'].sum()
    
    # Get top addresses by transaction count
    top_senders = received.groupby('from')['eth_value'].agg(['count', 'sum']).sort_values('count', ascending=False).head(5)
    top_receivers = sent.groupby('to')['eth_value'].agg(['count', 'sum']).sort_values('count', ascending=False).head(5)
    
    # Get top addresses by value
    top_senders_by_value = received.groupby('from')['eth_value'].sum().sort_values(ascending=False).head(5)
    top_receivers_by_value = sent.groupby('to')['eth_value'].sum().sort_values(ascending=False).head(5)
    
    # Time-based analysis
    if 'timestamp' in df.columns:
        df['date'] = pd.to_datetime(df['timestamp'], unit='s')
        df['year_month'] = df['date'].dt.strftime('%Y-%m')
        
        # Transactions by month
        monthly_txns = df.groupby('year_month').size()
        
        # Value by month
        monthly_value = df.groupby('year_month')['eth_value'].sum()
    else:
        monthly_txns = None
        monthly_value = None
    
    return {
        'total_transactions': len(df),
        'sent_transactions': len(sent),
        'received_transactions': len(received),
        'unique_senders': unique_senders,
        'unique_receivers': unique_receivers,
        'total_sent': total_sent,
        'total_received': total_received,
        'net_balance': total_received - total_sent,
        'top_senders': top_senders.to_dict(),
        'top_receivers': top_receivers.to_dict(),
        'top_senders_by_value': top_senders_by_value.to_dict(),
        'top_receivers_by_value': top_receivers_by_value.to_dict(),
        'monthly_transactions': monthly_txns.to_dict() if monthly_txns is not None else None,
        'monthly_value': monthly_value.to_dict() if monthly_value is not None else None
    }