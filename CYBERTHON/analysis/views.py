from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from web3 import Web3
from etherscan import Etherscan
import pandas as pd
from datetime import datetime
import os
import re
import logging
import json
import sys
import networkx as nx
import matplotlib.pyplot as plt
# Update the import path to be relative to the analysis app
from .spider_map.fetch_and_store import spider_map
# Configure logging
logger = logging.getLogger(__name__)

ML_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ML', 'python_codes')
sys.path.append(ML_DIR)

from predict_risk import risk_score


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
    """Fetch transactions and risk metrics for a given wallet address."""
    wallet_address = request.GET.get("wallet_address")
    
    try:
        # Fetch normal transaction data from Etherscan
        normal_txs = eth.get_normal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
        internal_txs = eth.get_internal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')

        # Process transactions for visualization
        transactions = []
        for tx in (normal_txs or []):
            transactions.append({
                'from': tx['from'],
                'to': tx['to'],
                'eth_value': float(tx['value']) / 1e18,  # Convert from Wei to ETH
                'timestamp': int(tx['timeStamp']),
                'txn_type': 'sent' if tx['from'].lower() == wallet_address.lower() else 'received'
            })

        # Prepare response data
        response_data = {
            "message": "Transaction data fetched successfully",
            "transactions": transactions,
            "features": {
                "total_transactions": len(transactions),
                "unique_addresses": len(set(tx['from'] for tx in transactions) | set(tx['to'] for tx in transactions))
            }
        }

        return JsonResponse(response_data)

    except Exception as e:
        logger.error(f"Error processing wallet {wallet_address}: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

def generate_spider_map(request):
    """Generate spider map visualization for wallet transactions."""
    try:
        wallet_address = request.GET.get('wallet_address')
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        
        if not all([wallet_address, start_date, end_date]):
            return JsonResponse({"error": "Missing required parameters"}, status=400)
        
        # Ensure wallet address is lowercase
        wallet_address = wallet_address.lower()
        
        # Convert dates to required format (YYYY-MM-DD)
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').strftime('%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d').strftime('%Y-%m-%d')
        except ValueError:
            return JsonResponse({"error": "Invalid date format. Use YYYY-MM-DD"}, status=400)
            
        # Generate the spider map
        spider_map.main(wallet_address, start_date, end_date)
        
        # Get the path to the generated master.html in the spider_map directory
        master_html_path = os.path.join(os.path.dirname(__file__), 'spider_map', 'master.html')
        
        if not os.path.exists(master_html_path):
            return JsonResponse({"error": "Visualization file not generated"}, status=500)
            
        with open(master_html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        return HttpResponse(html_content, content_type='text/html')
        
    except Exception as e:
        logger.error(f"Error generating spider map: {str(e)}")
        return JsonResponse({"error": f"Failed to generate visualization: {str(e)}"}, status=500)

def fetch_risk_metrics(request):
    """Separate endpoint to fetch risk metrics for a wallet address."""
    wallet_address = request.GET.get("wallet_address")
    
    # Validate input
    if not wallet_address:
        return JsonResponse({"error": "Wallet address is required"}, status=400)
    
    if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
        return JsonResponse({"error": "Invalid Ethereum address format"}, status=400)

    try:
        # Get risk metrics
        metrics = risk_score.get_risk_score(wallet_address)
        
        # Keep the original structure exactly as it is expected by the frontend
        # Don't rename or restructure the fields
        return JsonResponse({
            "risk_score": metrics["risk_score"],
            "total_eth": metrics["total_eth"],
            "total_transactions": metrics["total_transactions"],
            "Avg min between sent tnx": metrics["Avg min between sent tnx"],
            "Avg min between received tnx": metrics["Avg min between received tnx"],
            "Time Diff between first and last (Mins)": metrics["Time Diff between first and last (Mins)"],
            "Sent tnx": metrics["Sent tnx"],
            "Received Tnx": metrics["Received Tnx"],
            "Unique Received From Addresses": metrics["Unique Received From Addresses"],
            "Unique Sent To Addresses": metrics["Unique Sent To Addresses"],
            "max value received ": metrics["max value received "],
            "avg val received": metrics["avg val received"],
            "max val sent": metrics["max val sent"],
            "avg val sent": metrics["avg val sent"],
            "total Ether sent": metrics["total Ether sent"],
            "total ether received": metrics["total ether received"],
            "total ether balance": metrics["total ether balance"]
        })

    except Exception as e:
        logger.error(f"Error fetching risk metrics for wallet {wallet_address}: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch risk metrics: {str(e)}"}, status=500)