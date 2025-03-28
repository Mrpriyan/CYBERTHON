from etherscan import Etherscan
from web3 import Web3
import pandas as pd
from datetime import datetime
import time
import os

class EthereumWalletDataExtractor:
    def __init__(self, api_key):
        """Initialize the extractor with Etherscan API key"""
        self.eth = Etherscan(api_key)
        self.web3 = Web3()
    
    def extract_wallet_features(self, wallet_address):
        """Extract specific features for a wallet address"""
        # Fetch normal transactions
        try:
            normal_txs = self.eth.get_normal_txs_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
            normal_df = pd.DataFrame(normal_txs)
            
            if normal_df.empty:
                normal_df = pd.DataFrame(columns=['from', 'to', 'value', 'timeStamp'])
        except Exception as e:
            normal_df = pd.DataFrame(columns=['from', 'to', 'value', 'timeStamp'])
        
        # Process normal transactions
        if not normal_df.empty:
            normal_df['eth_value'] = normal_df['value'].apply(lambda x: float(Web3.from_wei(int(x), 'ether')))
            normal_df['timestamp'] = normal_df['timeStamp'].astype(int)
            normal_df['datetime'] = normal_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            normal_df['is_contract_creation'] = normal_df['to'].apply(lambda x: 1 if x == '' else 0)
        
        # Separate sent and received transactions
        sent_txns = normal_df[normal_df['from'].str.lower() == wallet_address.lower()] if not normal_df.empty else pd.DataFrame()
        received_txns = normal_df[normal_df['to'].str.lower() == wallet_address.lower()] if not normal_df.empty else pd.DataFrame()
        
        # Identify contract interactions
        if not sent_txns.empty:
            sent_txns.loc[:, 'is_contract_interaction'] = sent_txns['input'].apply(lambda x: 1 if x != '0x' else 0)
            contract_txns = sent_txns[sent_txns['is_contract_interaction'] == 1]
        else:
            contract_txns = pd.DataFrame()
        
        # To avoid rate limiting
        time.sleep(1)
        
        # Fetch ERC20 Token Transfer Events
        try:
            erc20_txs = self.eth.get_erc20_token_transfer_events_by_address(wallet_address, startblock=0, endblock=99999999, sort='asc')
            erc20_df = pd.DataFrame(erc20_txs)
        except Exception as e:
            erc20_df = pd.DataFrame(columns=['from', 'to', 'value', 'tokenName', 'tokenSymbol', 'timeStamp'])
        
        # Process ERC20 transactions
        if not erc20_df.empty:
            erc20_df['timestamp'] = erc20_df['timeStamp'].astype(int)
            erc20_df['datetime'] = erc20_df['timestamp'].apply(lambda x: datetime.utcfromtimestamp(x))
            
            # Convert token value based on decimals
            erc20_df['token_value'] = erc20_df.apply(
                lambda row: float(row['value']) / (10 ** int(row.get('tokenDecimal', 18))), axis=1
            )
        
        # Separate ERC20 sent and received transactions
        erc20_sent = erc20_df[erc20_df['from'].str.lower() == wallet_address.lower()] if not erc20_df.empty else pd.DataFrame()
        erc20_received = erc20_df[erc20_df['to'].str.lower() == wallet_address.lower()] if not erc20_df.empty else pd.DataFrame()
        
        # Calculate the requested features
        features = {
            "Address": wallet_address,
            "FLAG": 0,  # Default to non-fraudulent
            "Avg min between sent tnx": sent_txns['timestamp'].diff().mean() / 60 if len(sent_txns) > 1 else 0,
            "Avg min between received tnx": received_txns['timestamp'].diff().mean() / 60 if len(received_txns) > 1 else 0,
            "Time Diff between first and last (Mins)": (normal_df['timestamp'].max() - normal_df['timestamp'].min()) / 60 if not normal_df.empty and len(normal_df) > 1 else 0,
            "Sent tnx": len(sent_txns),
            "Received Tnx": len(received_txns),
            "Unique Received From Addresses": received_txns['from'].nunique() if not received_txns.empty else 0,
            "Unique Sent To Addresses": sent_txns['to'].nunique() if not sent_txns.empty else 0,
            "max value received ": received_txns['eth_value'].max() if not received_txns.empty else 0,
            "avg val received": received_txns['eth_value'].mean() if not received_txns.empty else 0,
            "max val sent": sent_txns['eth_value'].max() if not sent_txns.empty else 0,
            "avg val sent": sent_txns['eth_value'].mean() if not sent_txns.empty else 0,
            "total Ether sent": sent_txns['eth_value'].sum() if not sent_txns.empty else 0,
            "total ether received": received_txns['eth_value'].sum() if not received_txns.empty else 0,
            "total ether balance": (received_txns['eth_value'].sum() if not received_txns.empty else 0) - 
                                  (sent_txns['eth_value'].sum() if not sent_txns.empty else 0),
            "Number of Created Contracts": sent_txns['is_contract_creation'].sum() if not sent_txns.empty else 0,
            "max val sent to contract": contract_txns['eth_value'].max() if not contract_txns.empty else 0,
            "total ether sent contracts": contract_txns['eth_value'].sum() if not contract_txns.empty else 0,
            " Total ERC20 tnxs": len(erc20_df),
            " ERC20 total ether sent": erc20_sent['token_value'].sum() if not erc20_sent.empty else 0,
            " ERC20 avg time between sent tnx": erc20_sent['timestamp'].diff().mean() / 60 if len(erc20_sent) > 1 else 0,
            " ERC20 max val sent": erc20_sent['token_value'].max() if not erc20_sent.empty else 0,
            " ERC20 uniq sent addr": erc20_sent['to'].nunique() if not erc20_sent.empty else 0,
            " ERC20 uniq rec addr": erc20_received['from'].nunique() if not erc20_received.empty else 0,
        }
        
        return features

    def process_wallets(self, addresses):
        """Process multiple wallet addresses and compile results"""
        all_data = []
        
        for idx, address in enumerate(addresses):
            #print(f"Processing wallet {idx+1}/{len(addresses)}")
            try:
                features = self.extract_wallet_features(address)
                all_data.append(features)
                # Sleep to avoid API rate limits
                time.sleep(1)
            except Exception as e:
                pass
                #print(f"Error processing wallet {address}: {str(e)}")
        
        # Create DataFrame with results
        df = pd.DataFrame(all_data)
        
        # Reorder columns to match the requested format
        desired_columns = [
            "FLAG", "Avg min between sent tnx", "Avg min between received tnx", 
            "Time Diff between first and last (Mins)", "Sent tnx", "Received Tnx",
            "Unique Received From Addresses", "Unique Sent To Addresses",
            "max value received ", "avg val received", "max val sent", "avg val sent",
            "total Ether sent", "total ether received", "total ether balance",
            "Number of Created Contracts", "max val sent to contract", 
            "total ether sent contracts", " Total ERC20 tnxs", " ERC20 total ether sent",
            " ERC20 avg time between sent tnx", " ERC20 max val sent",
            " ERC20 uniq sent addr", " ERC20 uniq rec addr", "Address"
        ]
        
        # Ensure all columns exist
        for col in desired_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Reorder columns
        df = df[desired_columns]
        
        return df

def main():
    # Get API key
    api_key ="848HZHG8QKCE4DIMBV7P13CDSUARHXDX4T"
    extractor = EthereumWalletDataExtractor(api_key)
    
    # Choose input method
    choice = input("Enter (1) for single wallet address or (2) for file with multiple addresses: ")
    
    if choice == '1':
        address = input("Enter Ethereum wallet address: ")
        addresses = [address]
    elif choice == '2':
        file_path = input("Enter path to file with wallet addresses (one per line): ") or "csv_files\\wallet_addresses.csv"
        try:
            with open(file_path, 'r') as f:
                addresses = [line.strip() for line in f if line.strip()]
        except Exception as e:
            #print(f"Error reading file: {str(e)}")
            return
    else:
        #print("Invalid choice")
        return
    
    # Process wallets
    result_df = extractor.process_wallets(addresses)
    
    # Save results
    output_file = input("Enter output file name (default: wallet_data.csv): ") or "csv_files\\wallet_data.csv"
    result_df.to_csv(output_file, index=False)
    #print(f"Analysis complete. Results saved to {output_file}")
    
    # Print summary
    #print("\nSummary:")
    #print(f"Processed {len(result_df)} wallet addresses")
    #print(f"Selected {len(result_df.columns)} features per wallet")

if __name__ == "__main__":
    main()