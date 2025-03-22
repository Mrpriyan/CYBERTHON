import re
import pandas as pd
import joblib
from datetime import datetime
from fetch import EthereumWalletDataExtractor
from enhanced_rf_model_genrator import OptimizedEthereumFraudDetector

def is_valid_ethereum_address(address):
    """Validate if the given address is a valid Ethereum address."""
    pattern = r"^0x[a-fA-F0-9]{40}$"
    return re.match(pattern, address) is not None

if __name__ == "__main__":
    # Paths to the model files
    model_path = "models\\optimized_ethereum_fraud_model.pkl"
    scaler_path = "other_opti_features\\optimized_scaler.pkl"
    features_path = "other_opti_features\\optimized_features.pkl"

    # Initialize the detector and load the model first
    detector = OptimizedEthereumFraudDetector(model_path, scaler_path, features_path)
    if not detector.load_model():
        print("No existing model found. Training initial model...")
        detector.train("csv_files\\enhanced_trained_dataset.csv")

    # Get wallet address input after model is ready
    wallet_address = input("Enter the wallet address: ").strip()

    # Validate the wallet address
    if not is_valid_ethereum_address(wallet_address):
        print("Error: The entered wallet address is not a valid Ethereum address.")
        exit(1)

    # Initialize the wallet data extractor
    extractor = EthereumWalletDataExtractor(api_key="848HZHG8QKCE4DIMBV7P13CDSUARHXDX4T")

    # Fetch wallet transactions
    wallet_addresses = [wallet_address]
    wallet_data = extractor.process_wallets(wallet_addresses)

    # Save the transaction data
    wallet_data.to_csv("csv_files\\wallet_data.csv", index=False)
    print("Wallet data saved to csv_files\\wallet_data.csv")
    
    # Make predictions using current model
    results = []
    for _, row in wallet_data.iterrows():
        wallet_dict = row.to_dict()
        prediction = detector.predict_risk(wallet_dict)
        results.append(prediction)

    # Save prediction results
    results_df = pd.DataFrame(results)
    analyzed_results_path = "csv_files\\analyzed_wallet_results.csv"
    if not pd.io.common.file_exists(analyzed_results_path):
        results_df.to_csv(analyzed_results_path, index=False)
    else:
        results_df.to_csv(analyzed_results_path, mode='a', index=False, header=False)

    # Save transaction data for future training
    analyzed_data_path = "csv_files\\analyzed_wallet_datas.csv"
    if not pd.io.common.file_exists(analyzed_data_path):
        wallet_data.to_csv(analyzed_data_path, index=False)
    else:
        wallet_data.to_csv(analyzed_data_path, mode='a', index=False, header=False)

    # Print the current prediction results
    for result in results:
        for k, v in result.items():
            print(f"{k}: {v}")

    # Ask if user wants to retrain the model
    retrain_choice ='y'
    if retrain_choice in ['yes', 'y']:
        # Retrain and compare models
        detector.retrain_and_compare("csv_files\\enhanced_trained_dataset.csv")
    else:
        print("Skipping model retraining.")