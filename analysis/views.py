from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from web3 import Web3
from etherscan import Etherscan
import pandas as pd
from datetime import datetime
import os
import re
import logging
import json
# Configure logging
logger = logging.getLogger(__name__)

# Initialize Etherscan API (API key should ideally be in settings.py)
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "848HZHG8QKCE4DIMBV7P13CDSUARHXDX4T")  # Use env var or fallback
eth = Etherscan(ETHERSCAN_API_KEY)

def home(request):
    """Render the home page."""
    return render(request, "analysis/home.html")

def about(request):
    """Render the about page."""
    return render(request, "analysis/about.html")

def forpdf(request):
    """Render the page for PDF generation."""
    return render(request, "analysis/forpdf.html")

def analyze_transactions(request):
    """Render the analyze transactions page where users input a wallet address."""
    return render(request, "analysis/analyze_transactions.html")


def fetch_all_transaction(request):
    """Fetch transactions from Etherscan and generate insights for a given wallet address."""
    wallet_address = request.GET.get("wallet_address")  # Get wallet from query parameter
    
    # Validate input
    if not wallet_address:
        return JsonResponse({"error": "Wallet address is required"}, status=400)
    
    if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
        return JsonResponse({"error": "Invalid Ethereum address format"}, status=400)

    try:
        # Fetch normal transaction data from Etherscan
        normal_txs = eth.get_normal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
        
        # Fetch internal transaction data
        internal_txs = eth.get_internal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
        
        if not normal_txs and not internal_txs:
            return JsonResponse({"error": "No transactions found for this wallet"}, status=404)

        # Process normal transactions
        normal_df = pd.DataFrame(normal_txs) if normal_txs else pd.DataFrame()
        if not normal_df.empty:
            normal_df['eth_value'] = normal_df['value'].apply(lambda x: float(Web3.from_wei(int(x), 'ether')))
            normal_df['txn_type'] = normal_df.apply(
                lambda row: 'sent' if row['from'].lower() == wallet_address.lower() else 'received', 
                axis=1
            )
            normal_df['timestamp'] = normal_df['timeStamp'].astype(int)
            normal_df['datetime'] = normal_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            normal_df['transaction_type'] = 'normal'
        
        # Process internal transactions
        internal_df = pd.DataFrame(internal_txs) if internal_txs else pd.DataFrame()
        if not internal_df.empty:
            internal_df['eth_value'] = internal_df['value'].apply(lambda x: float(Web3.from_wei(int(x), 'ether')))
            internal_df['txn_type'] = internal_df.apply(
                lambda row: 'sent' if row['from'].lower() == wallet_address.lower() else 'received', 
                axis=1
            )
            internal_df['timestamp'] = internal_df['timeStamp'].astype(int)
            internal_df['datetime'] = internal_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            internal_df['transaction_type'] = 'internal'
        
        # Combine normal and internal transactions
        common_columns = ['hash', 'from', 'to', 'eth_value', 'txn_type', 'timestamp', 'datetime', 'transaction_type']
        
        if normal_df.empty:
            combined_df = internal_df[internal_df.columns.intersection(common_columns)]
        elif internal_df.empty:
            combined_df = normal_df[normal_df.columns.intersection(common_columns)]
        else:
            normal_subset = normal_df[normal_df.columns.intersection(common_columns)]
            internal_subset = internal_df[internal_df.columns.intersection(common_columns)]
            combined_df = pd.concat([normal_subset, internal_subset], ignore_index=True)
        
        # Calculate metrics
        sent_txns = combined_df[combined_df['txn_type'] == 'sent']
        received_txns = combined_df[combined_df['txn_type'] == 'received']
        
        total_sent = float(sent_txns['eth_value'].sum()) if not sent_txns.empty else 0
        total_received = float(received_txns['eth_value'].sum()) if not received_txns.empty else 0
        
        features = {
            "Address": wallet_address,
            "Sent Transactions": len(sent_txns),
            "Received Transactions": len(received_txns),
            "Total Ether Sent": total_sent,
            "Total Ether Received": total_received,
            "Total Ether Balance": total_received - total_sent
        }

        # Save CSVs in static directory
        static_dir = os.path.join(settings.BASE_DIR, "static")
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)

        # Save combined transactions
        csv_filename = f"{wallet_address}_transactions.csv"
        csv_filepath = os.path.join(static_dir, csv_filename)
        combined_df.to_csv(csv_filepath, index=False)
        
        # Log successful fetch
        logger.info(f"Transactions fetched and saved for {wallet_address}")

        return JsonResponse({
            "message": "Transaction data fetched successfully",
            "features": features,
            "csv_download_link": f"{settings.STATIC_URL}{csv_filename}"
        })

    except Exception as e:
        # Log the error for debugging
        logger.error(f"Error fetching transactions for {wallet_address}: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch transactions: {str(e)}"}, status=500)

import networkx as nx
import matplotlib.pyplot as plt
import io
import base64

def generate_spider_map(wallet_address, transactions):
    """
    Generate a spider map showing transaction flows.
    
    Parameters:
    - wallet_address: The queried Ethereum wallet address.
    - transactions: List of transaction dictionaries.

    Returns:
    - Image URL (base64 encoded PNG)
    """
    G = nx.DiGraph()  # Directed graph

    # Add edges (from -> to) based on transactions
    for tx in transactions:
        sender = tx['from']
        receiver = tx['to']
        eth_value = tx['eth_value']

        if sender != receiver:  # Avoid self-transactions
            G.add_edge(sender, receiver, weight=eth_value)

    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G, seed=42)  # Positioning

    # Draw nodes and edges
    nx.draw(G, pos, with_labels=True, node_color='skyblue', edge_color='gray', node_size=2000, font_size=8)
    
    # Draw edge labels (transaction values)
    labels = {(tx['from'], tx['to']): f"{tx['eth_value']:.3f} ETH" for tx in transactions}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_size=7)

    # Save plot as an image
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{encoded_image}"

from django.http import JsonResponse
import requests

def fetch_all_transaction(request):
    """Fetch transactions from Etherscan and generate insights for a given wallet address."""
    wallet_address = request.GET.get("wallet_address")  # Get wallet from query parameter
    
    # Validate input
    if not wallet_address:
        return JsonResponse({"error": "Wallet address is required"}, status=400)
    
    if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
        return JsonResponse({"error": "Invalid Ethereum address format"}, status=400)

    try:
        # Fetch normal transaction data from Etherscan
        normal_txs = eth.get_normal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
        internal_txs = eth.get_internal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
        
        if not normal_txs and not internal_txs:
            return JsonResponse({"error": "No transactions found for this wallet"}, status=404)

        # Process normal transactions
        normal_df = pd.DataFrame(normal_txs) if normal_txs else pd.DataFrame()
        if not normal_df.empty:
            normal_df['eth_value'] = normal_df['value'].apply(lambda x: float(Web3.from_wei(int(x), 'ether')))
            normal_df['txn_type'] = normal_df.apply(
                lambda row: 'sent' if row['from'].lower() == wallet_address.lower() else 'received', 
                axis=1
            )
            normal_df['timestamp'] = normal_df['timeStamp'].astype(int)
            normal_df['datetime'] = normal_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            normal_df['transaction_type'] = 'normal'
        
        # Process internal transactions
        internal_df = pd.DataFrame(internal_txs) if internal_txs else pd.DataFrame()
        if not internal_df.empty:
            internal_df['eth_value'] = internal_df['value'].apply(lambda x: float(Web3.from_wei(int(x), 'ether')))
            internal_df['txn_type'] = internal_df.apply(
                lambda row: 'sent' if row['from'].lower() == wallet_address.lower() else 'received', 
                axis=1
            )
            internal_df['timestamp'] = internal_df['timeStamp'].astype(int)
            internal_df['datetime'] = internal_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            internal_df['transaction_type'] = 'internal'
        
        # Combine normal and internal transactions
        common_columns = ['hash', 'from', 'to', 'eth_value', 'txn_type', 'timestamp', 'datetime', 'transaction_type']
        if normal_df.empty:
            combined_df = internal_df[internal_df.columns.intersection(common_columns)]
        elif internal_df.empty:
            combined_df = normal_df[normal_df.columns.intersection(common_columns)]
        else:
            normal_subset = normal_df[normal_df.columns.intersection(common_columns)]
            internal_subset = internal_df[internal_df.columns.intersection(common_columns)]
            combined_df = pd.concat([normal_subset, internal_subset], ignore_index=True)
        
        # Convert combined_df to a list of dictionaries for JSON
        transactions = combined_df.to_dict(orient='records')
        
        # Calculate metrics
        sent_txns = combined_df[combined_df['txn_type'] == 'sent']
        received_txns = combined_df[combined_df['txn_type'] == 'received']
        
        total_sent = float(sent_txns['eth_value'].sum()) if not sent_txns.empty else 0
        total_received = float(received_txns['eth_value'].sum()) if not received_txns.empty else 0
        
        features = {
            "Address": wallet_address,
            "Sent Transactions": len(sent_txns),
            "Received Transactions": len(received_txns),
            "Total Ether Sent": total_sent,
            "Total Ether Received": total_received,
            "Total Ether Balance": total_received - total_sent
        }

        # Save CSVs in static directory
        static_dir = os.path.join(settings.BASE_DIR, "static")
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)

        csv_filename = f"{wallet_address}_transactions.csv"
        csv_filepath = os.path.join(static_dir, csv_filename)
        combined_df.to_csv(csv_filepath, index=False)
        
        logger.info(f"Transactions fetched and saved for {wallet_address}")

        return JsonResponse({
            "message": "Transaction data fetched successfully",
            "features": features,
            "transactions": transactions,  # Add transactions to the response
            "csv_download_link": f"{settings.STATIC_URL}{csv_filename}"
        })

    except Exception as e:
        logger.error(f"Error fetching transactions for {wallet_address}: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch transactions: {str(e)}"}, status=500)