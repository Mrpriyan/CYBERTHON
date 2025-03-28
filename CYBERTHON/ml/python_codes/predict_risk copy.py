import re
import pandas as pd
import joblib
from datetime import datetime
from fetch import EthereumWalletDataExtractor
from enhanced_rf_model_genrator import OptimizedEthereumFraudDetector

# Add this line at the top after imports to suppress the warning
pd.options.mode.chained_assignment = None

class risk_score:
    def is_valid_ethereum_address(address):
        """Validate if the given address is a valid Ethereum address."""
        pattern = r"^0x[a-fA-F0-9]{40}$"
        return re.match(pattern, address) is not None

    def get_risk_score(wallet_address):
        # Update paths to include ML directory
        model_path = "ML/models/optimized_ethereum_fraud_model.pkl"
        scaler_path = "ML/other_opti_features/optimized_scaler.pkl"
        features_path = "ML/other_opti_features/optimized_features.pkl"

        # Initialize the detector and load the model first
        detector = OptimizedEthereumFraudDetector(model_path, scaler_path, features_path)
        if not detector.load_model():
            detector.train("ML/csv_files/enhanced_trained_dataset.csv")

        # Validate the wallet address
        if not risk_score.is_valid_ethereum_address(wallet_address):
            exit(1)

        # Initialize the wallet data extractor
        extractor = EthereumWalletDataExtractor(api_key="848HZHG8QKCE4DIMBV7P13CDSUARHXDX4T")

        # Fetch wallet transactions
        wallet_addresses = [wallet_address]
        wallet_data = extractor.process_wallets(wallet_addresses)

        # Make predictions using current model
        results = []
        for _, row in wallet_data.iterrows():
            wallet_dict = row.to_dict()
            prediction = detector.predict_risk(wallet_dict)
            results.append(prediction)

        # Create the response dictionary with required fields
        response_dict = {
            "risk_score": results[0]['risk_score']*100 if results else 0,
            "total_eth":float(row['total Ether sent'])+float(row['total ether received']),
            "total_transactions": int(row['Sent tnx']) + int(row['Received Tnx']),
            "Avg min between sent tnx": float(row['Avg min between sent tnx']),
            "Avg min between received tnx": float(row['Avg min between received tnx']),
            "Time Diff between first and last (Mins)": float(row['Time Diff between first and last (Mins)']),
            "Sent tnx": int(row['Sent tnx']),
            "Received Tnx": int(row['Received Tnx']),
            "Unique Received From Addresses": int(row['Unique Received From Addresses']),
            "Unique Sent To Addresses": int(row['Unique Sent To Addresses']),
            "max value received ": float(row['max value received ']),
            "avg val received": float(row['avg val received']),
            "max val sent": float(row['max val sent']),
            "avg val sent": float(row['avg val sent']),
            "total Ether sent": float(row['total Ether sent']),
            "total ether received": float(row['total ether received']),
            "total ether balance": float(row['total ether balance'])
        }

        # Save data for future use
        wallet_data.to_csv("ML/csv_files/wallet_data.csv", index=False)
        
        # Save prediction results
        results_df = pd.DataFrame(results)
        analyzed_results_path = "ML/csv_files/analyzed_wallet_results.csv"
        if not pd.io.common.file_exists(analyzed_results_path):
            results_df.to_csv(analyzed_results_path, index=False)
        else:
            results_df.to_csv(analyzed_results_path, mode='a', index=False, header=False)

        # Save transaction data
        analyzed_data_path = "ML/csv_files/analyzed_wallet_datas.csv"
        if not pd.io.common.file_exists(analyzed_data_path):
            wallet_data.to_csv(analyzed_data_path, index=False)
        else:
            wallet_data.to_csv(analyzed_data_path, mode='a', index=False, header=False)

        return response_dict

