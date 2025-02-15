import requests
import networkx as nx
from django.shortcuts import render
from django.http import JsonResponse
from pyvis.network import Network
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.http import JsonResponse

MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6ImZmNmE5NmEzLWE5NjUtNDEwNy1iZGIyLTI5N2E2YTc4NzI2NSIsIm9yZ0lkIjoiNDI5NDYyIiwidXNlcklkIjoiNDQxNzQ5IiwidHlwZUlkIjoiY2E3YjA5N2YtYzE3Mi00MTIzLTg5MTQtMmI5MmUyNTM0MDFiIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3Mzg2ODczNzksImV4cCI6NDg5NDQ0NzM3OX0.8RLifPzimTbzeBqnY4Q9AiWb2GdyEIKExDv34m46If8"

def home(request):
    """Render the home page."""
    return render(request, "analysis/home.html")

def about(request):
    """Render the about page."""
    return render(request, "analysis/about.html")


def forpdf(request):
    return render(request, 'analysis/forpdf.html')




def generate_transaction_charts(transactions):
    """
    Generate data for pie charts showing transaction distribution
    by count and amount for both sending and receiving addresses.
    
    Args:
        transactions (list): List of transaction dictionaries from Moralis API
        
    Returns:
        dict: Dictionary containing data for four pie charts:
            - sender_counts: Distribution of number of transactions by sender
            - receiver_counts: Distribution of number of transactions by receiver
            - sender_amounts: Distribution of total amounts by sender
            - receiver_amounts: Distribution of total amounts by receiver
    """
    if not transactions:
        return {
            "sender_counts": [],
            "receiver_counts": [],
            "sender_amounts": [],
            "receiver_amounts": []
        }
    
    # Initialize dictionaries to store counts and amounts
    sender_counts = {}
    receiver_counts = {}
    sender_amounts = {}
    receiver_amounts = {}
    
    # Process all transactions
    for tx in transactions:
        sender = tx.get("from_address", "").lower()
        receiver = tx.get("to_address", "").lower()
        # Convert value from Wei to ETH
        value = float(tx.get("value", "0")) / 10**18
        
        # Update transaction counts
        sender_counts[sender] = sender_counts.get(sender, 0) + 1
        receiver_counts[receiver] = receiver_counts.get(receiver, 0) + 1
        
        # Update transaction amounts
        sender_amounts[sender] = sender_amounts.get(sender, 0) + value
        receiver_amounts[receiver] = receiver_amounts.get(receiver, 0) + value
    
    # Function to format address data for charts
    def format_data(data_dict, top_n=5):
        # Sort by value in descending order and take top N
        sorted_data = sorted(data_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
        # Format addresses to be shorter
        return [
            {
                "address": f"{addr[:6]}...{addr[-4:]}" if len(addr) > 10 else addr,
                "value": round(value, 4),
                "full_address": addr  # Keep full address for reference
            }
            for addr, value in sorted_data
        ]
    
    # Generate final chart data
    chart_data = {
        "sender_counts": format_data(sender_counts),
        "receiver_counts": format_data(receiver_counts),
        "sender_amounts": format_data(sender_amounts),
        "receiver_amounts": format_data(receiver_amounts)
    }
    
    return chart_data




def fetch_transactions(wallet_address, chain="eth"):
    """Fetch transactions using Moralis API with enhanced error handling and debugging."""
    url = f"https://deep-index.moralis.io/api/v2/{wallet_address}?chain={chain}"
    
    headers = {"X-API-Key": MORALIS_API_KEY}
    try:
        print(f"Fetching transactions for wallet: {wallet_address}")  # Debug print
        response = requests.get(url, headers=headers)
        print(f"API Response Status Code: {response.status_code}")  # Debug print
        
        # Print the first part of the response for debugging
        print(f"API Response: {response.text[:500]}")  # Show first 500 chars
        
        response.raise_for_status()
        data = response.json()
        
        # Additional validation
        if not isinstance(data, dict):
            print(f"Unexpected response format: {type(data)}")
            return []
            
        transactions = data.get("result", [])
        print(f"Found {len(transactions)} transactions")  # Debug print
        
        if not transactions:
            # Check if the wallet address is valid
            if not is_valid_ethereum_address(wallet_address):
                print(f"Invalid Ethereum address format: {wallet_address}")
                return []
                
            # Check if the wallet exists but has no transactions
            print("No transactions found for this wallet")
            return []
            
        return transactions
        
    except requests.RequestException as e:
        print(f"API Request Error: {str(e)}")
        return []
    except ValueError as e:
        print(f"JSON Parsing Error: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        return []


def is_valid_ethereum_address(address):
    """Validate Ethereum address format."""
    import re
    # Check if address matches Ethereum address format (0x followed by 40 hex characters)
    pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')
    return bool(pattern.match(address))


@csrf_exempt
def home(request):
    """Enhanced home view with better error handling."""
    if request.method == "POST":
        wallet_address = request.POST.get("wallet_address", "").strip()
        chain = request.POST.get("chain", "eth")
        
        if not wallet_address:
            return JsonResponse({
                "status": "error",
                "message": "Wallet address is required"
            })
            
        if not is_valid_ethereum_address(wallet_address):
            return JsonResponse({
                "status": "error",
                "message": "Invalid Ethereum address format"
            })
        
        # Fetch transactions
        transactions = fetch_transactions(wallet_address, chain)
        
        if not transactions:
            return JsonResponse({
                "status": "warning",
                "message": "No transactions found for this wallet",
                "data": {
                    "wallet_address": wallet_address,
                    "total_transactions": 0,
                    "transaction_volume": 0,
                    "fraud_score": 0,
                    "suspicious_activities": []
                }
            })
        
        # Generate new visualization only if we have transactions
        # Pass the wallet_address as central_address
        graph_success = generate_spider_graph(transactions, central_address=wallet_address)
        
        # Analyze transactions
        analysis_results = analyze_transactions(wallet_address, transactions)
        
        if not graph_success:
            analysis_results["graph_error"] = "Failed to generate transaction graph"
        
        return JsonResponse({
            "status": "success",
            "message": "Analysis complete!",
            "data": analysis_results
        })
    
    return render(request, "analysis/home.html")


def generate_spider_graph(transactions, central_address, history=None):
    """Generate an interactive graph visualization with navigation history."""
    if not transactions:
        return False
    
    net = Network(height="600px", width="100%", directed=True, notebook=False)
    
    net.html = """
    <script>
    network.on("click", function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = network.body.data.nodes.get(nodeId);
            if (node.custom_properties && node.custom_properties.address) {
                // Send message to parent window
                window.parent.postMessage({
                    type: 'nodeClick',
                    address: node.custom_properties.address
                }, '*');
            }
        }
    });
    </script>
    """ + net.html


    # Add navigation controls to the HTML
    net.html = """
    <div class="navigation-controls" style="position: absolute; top: 10px; left: 10px; z-index: 999;">
        <button id="backButton" onclick="goBack()" style="padding: 5px 10px; margin-right: 5px;" disabled>
            ← Back
        </button>
        <button id="forwardButton" onclick="goForward()" style="padding: 5px 10px;" disabled>
            Forward →
        </button>
    </div>
    """ + net.html
    
    # Add central node
    net.add_node(central_address.lower(), 
                 color='#ff0000',
                 size=30,
                 title=f"Analyzed Wallet: {central_address}",
                 custom_properties={"address": central_address.lower()})
    
    # Track unique addresses and their transactions
    address_counts = {}
    transaction_details = {}
    
    for tx in transactions:
        sender = tx.get("from_address", "").lower()
        receiver = tx.get("to_address", "").lower()
        value = float(tx.get("value", "0")) / 10**18
        timestamp = tx.get("block_timestamp")
        
        # Update address counts and transaction details
        address_counts[sender] = address_counts.get(sender, 0) + 1
        address_counts[receiver] = address_counts.get(receiver, 0) + 1
        
        key = f"{sender}-{receiver}"
        if key not in transaction_details:
            transaction_details[key] = []
        transaction_details[key].append({
            "value": value,
            "timestamp": timestamp,
            "hash": tx.get("hash")
        })
        
        # Add nodes
        if sender not in net.nodes:
            net.add_node(sender,
                        color='#1f77b4',
                        title=f"Address: {sender}\nTransactions: {address_counts[sender]}",
                        custom_properties={"address": sender})
            
        if receiver not in net.nodes:
            net.add_node(receiver,
                        color='#1f77b4',
                        title=f"Address: {receiver}\nTransactions: {address_counts[receiver]}",
                        custom_properties={"address": receiver})
        
        # Add edge with accumulated transaction details
        edge_details = transaction_details[key]
        total_value = sum(tx["value"] for tx in edge_details)
        edge_title = f"Total: {total_value:.4f} ETH\nTransactions: {len(edge_details)}"
        
        net.add_edge(sender, receiver, 
                    title=edge_title,
                    value=min(total_value, 10),
                    arrows='to')
    
    # Add interaction handling
    net.options.interaction = {
        "hover": True,
        "navigationButtons": True,
        "keyboard": {
            "enabled": True,
            "speed": {"x": 10, "y": 10, "zoom": 0.1},
            "bindToWindow": True
        }
    }
    
    # Add custom JavaScript for node interaction and navigation
    net.html += """
    <script>
    let addressHistory = [];
    let currentIndex = -1;
    let network;
    
    function initNetwork() {
        network = document.getElementById('mynetwork').visNetwork;
        
        network.on('click', function(params) {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = network.body.data.nodes.get(nodeId);
                if (node.custom_properties && node.custom_properties.address) {
                    exploreNode(node.custom_properties.address);
                }
            }
        });
    }
    
    function exploreNode(address) {
        // Remove forward history if we're not at the end
        if (currentIndex < addressHistory.length - 1) {
            addressHistory = addressHistory.slice(0, currentIndex + 1);
        }
        
        // Add new address to history
        addressHistory.push(address);
        currentIndex++;
        
        // Update buttons
        updateNavigationButtons();
        
        // Fetch and display new transactions
        fetchNodeTransactions(address);
    }
    
    function goBack() {
        if (currentIndex > 0) {
            currentIndex--;
            fetchNodeTransactions(addressHistory[currentIndex]);
            updateNavigationButtons();
        }
    }
    
    function goForward() {
        if (currentIndex < addressHistory.length - 1) {
            currentIndex++;
            fetchNodeTransactions(addressHistory[currentIndex]);
            updateNavigationButtons();
        }
    }
    
    function updateNavigationButtons() {
        document.getElementById('backButton').disabled = currentIndex <= 0;
        document.getElementById('forwardButton').disabled = currentIndex >= addressHistory.length - 1;
    }
    
    function fetchNodeTransactions(address) {
        fetch('/analyze_node/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `wallet_address=${address}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Update the graph
                document.getElementById('graphFrame').src = '/static/graph.html?t=' + new Date().getTime();
            }
        })
        .catch(error => console.error('Error:', error));
    }
    
    // Initialize network when ready
    window.addEventListener('load', initNetwork);
    </script>
    """
    
    try:
        net.save_graph("static/graph.html")
        return True
    except Exception as e:
        print(f"Error saving graph: {e}")
        return False

@csrf_exempt
def analyze_node(request):
    """Handle requests to analyze specific nodes when clicked."""
    if request.method == "POST":
        wallet_address = request.POST.get("wallet_address", "").strip()
        
        if not wallet_address:
            return JsonResponse({
                "status": "error",
                "message": "Wallet address is required"
            })
        
        # Fetch transactions for the clicked node
        transactions = fetch_transactions(wallet_address)
        
        if not transactions:
            return JsonResponse({
                "status": "warning",
                "message": "No transactions found for this address",
                "data": {
                    "wallet_address": wallet_address,
                    "total_transactions": 0,
                    "transaction_volume": 0,
                    "graph": None,
                    "analysis": {
                        "total_transactions": 0,
                        "transaction_volume": 0,
                        "fraud_score": 0,
                        "suspicious_activities": []
                    }
                }
            })
        
        # Generate graph data
        graph_data = generate_graph_data(transactions, wallet_address)
        
        # Analyze transactions
        analysis_results = analyze_transactions(wallet_address, transactions)
        
        return JsonResponse({
            "status": "success",
            "message": "Node analysis complete",
            "data": {
                "graph": graph_data,
                "analysis": analysis_results
            }
        })
    
    return JsonResponse({
        "status": "error",
        "message": "Invalid request method"
    })

def generate_graph_data(transactions, central_address):
    """Generate graph data structure for visualization."""
    nodes = []
    edges = []
    address_counts = {}
    
    # Add central node
    nodes.append({
        "id": central_address.lower(),
        "label": f"Analyzed: {central_address[:8]}...",
        "color": "#ff0000",
        "size": 30,
        "custom_properties": {"address": central_address.lower()}
    })
    
    for tx in transactions:
        sender = tx.get("from_address", "").lower()
        receiver = tx.get("to_address", "").lower()
        value = float(tx.get("value", "0")) / 10**18
        
        # Update address counts
        address_counts[sender] = address_counts.get(sender, 0) + 1
        address_counts[receiver] = address_counts.get(receiver, 0) + 1
        
        # Add nodes if they don't exist
        for address in [sender, receiver]:
            if not any(node["id"] == address for node in nodes):
                nodes.append({
                    "id": address,
                    "label": f"{address[:8]}...",
                    "color": "#1f77b4",
                    "size": 20,
                    "custom_properties": {"address": address}
                })
        
        # Add edge
        edges.append({
            "from": sender,
            "to": receiver,
            "value": min(value, 10),
            "title": f"{value:.4f} ETH"
        })
    
    return {
        "nodes": nodes,
        "edges": edges
    }

@csrf_exempt
def analyze_transactions_view(request):
    """Enhanced analyze transactions view with better error handling."""
    if request.method == "POST":
        wallet_address = request.POST.get("wallet_address", "").strip()
        chain = request.POST.get("chain", "eth")
        
        if not wallet_address:
            return JsonResponse({
                "status": "error",
                "message": "Wallet address is required"
            })
            
        if not is_valid_ethereum_address(wallet_address):
            return JsonResponse({
                "status": "error",
                "message": "Invalid Ethereum address format"
            })
        
        # Fetch transactions
        transactions = fetch_transactions(wallet_address, chain)
        
        if not transactions:
            return JsonResponse({
                "status": "warning",
                "message": "No transactions found for this wallet",
                "data": {
                    "wallet_address": wallet_address,
                    "total_transactions": 0,
                    "transaction_volume": 0,
                    "fraud_score": 0,
                    "suspicious_activities": []
                }
            })
        
        # Generate new visualization only if we have transactions
        # Pass the wallet_address as central_address
        graph_success = generate_spider_graph(transactions, central_address=wallet_address)
        
        # Analyze transactions
        analysis_results = analyze_transactions(wallet_address, transactions)
        
        if not graph_success:
            analysis_results["graph_error"] = "Failed to generate transaction graph"
        
        return JsonResponse({
            "status": "success",
            "message": "Analysis complete!",
            "data": analysis_results
        })
    
    return render(request, "analysis/analyze_transactions.html")

def analyze_transactions(wallet_address, transactions):
    """Analyze transactions for suspicious patterns and generate a fraud score."""
    if not transactions:
        return {
            "wallet_address": wallet_address,
            "total_transactions": 0,
            "transaction_volume": 0,
            "fraud_score": 0,
            "suspicious_activities": [],
            "chart_data": None
        }
    
    total_volume = sum(float(tx.get("value", 0)) / 10**18 for tx in transactions)
    transaction_count = len(transactions)
    fraud_score = 0
    suspicious_patterns = []
    
    # Example blacklisted addresses (Replace with real data)
    blacklisted_addresses = {"0xabc123...", "0xdef456..."} 
    
    address_counts = {}
    for tx in transactions:
        sender = tx.get("from_address", "").lower()
        receiver = tx.get("to_address", "").lower()
        
        address_counts[sender] = address_counts.get(sender, 0) + 1
        address_counts[receiver] = address_counts.get(receiver, 0) + 1
        
        if sender in blacklisted_addresses or receiver in blacklisted_addresses:
            fraud_score += 40
            suspicious_patterns.append(f"Transaction with blacklisted address: {sender if sender in blacklisted_addresses else receiver}")
        
        if sender == receiver:
            fraud_score += 20
            suspicious_patterns.append("Self-transfer detected (potential mixing behavior)")
    
    # Detect rapid transaction bursts
    if transaction_count > 50:
        fraud_score += 30
        suspicious_patterns.append("High transaction volume detected in a short period")
    
    # Identify suspicious spikes in transaction volume
    if total_volume > 1000:
        fraud_score += 25
        suspicious_patterns.append("Unusual transaction volume detected (>1000 ETH)")
    
    # Check for transactions with multiple unique addresses (could indicate layering or mixing)
    unique_addresses = len(address_counts)
    if unique_addresses > 30:
        fraud_score += 20
        suspicious_patterns.append("Multiple unique transaction partners detected (possible layering activity)")
    
    # Cap fraud score at 100
    fraud_score = min(fraud_score, 100)
    
    chart_data = generate_transaction_charts(transactions)
    
    return {
        "wallet_address": wallet_address,
        "total_transactions": transaction_count,
        "transaction_volume": total_volume,
        "fraud_score": fraud_score,
        "suspicious_activities": suspicious_patterns,
        "chart_data": chart_data  # Add the chart data to the response
    }
