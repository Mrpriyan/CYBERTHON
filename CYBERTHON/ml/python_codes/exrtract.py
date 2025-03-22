import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns

def extract_essential_features(input_file, output_file):
    """Extract essential features from the training dataset and save to a new CSV file."""
    print(f"Loading data from {input_file}...")
    df = pd.read_csv(input_file)
    
    # List of features to keep (carefully selected based on relevance to fraud detection)
    essential_features = [
        # Target variable
        'FLAG',
        
        # Transaction patterns (frequency and timing)
        'Avg min between sent tnx',
        'Avg min between received tnx',
        'Time Diff between first and last (Mins)',
        'Sent tnx',
        'Received Tnx',
        
        # Transaction network characteristics
        'Unique Received From Addresses',
        'Unique Sent To Addresses',
        
        # Value-based features (ETH transactions)
        'max value received ',
        'avg val received',
        'max val sent',
        'avg val sent',
        'total Ether sent',
        'total ether received',
        'total ether balance',
        
        # Contract interactions (high-risk indicators)
        'Number of Created Contracts',
        'max val sent to contract',
        'total ether sent contracts',
        
        # ERC20 Token activities (key indicators)
        ' Total ERC20 tnxs',
        ' ERC20 total ether sent',
        ' ERC20 avg time between sent tnx',
        ' ERC20 max val sent',
        ' ERC20 uniq sent addr',
        ' ERC20 uniq rec addr',
    ]
    
    # Check which columns actually exist in the dataset
    available_columns = []
    missing_columns = []
    for col in essential_features:
        if col in df.columns:
            available_columns.append(col)
        else:
            missing_columns.append(col)
    
    if missing_columns:
        print(f"Warning: The following columns were not found in the dataset: {missing_columns}")
    
    # Keep only the essential features (that are available)
    df_essential = df[available_columns]
    
    # Also keep the Address column for reference if available
    if 'Address' in df.columns:
        df_essential['Address'] = df['Address']
    
    # Save to new CSV file
    df_essential.to_csv(output_file, index=False)
    print(f"Essential features saved to {output_file}")
    print(f"Reduced from {len(df.columns)} to {len(df_essential.columns)} features")
    
    return df_essential

def evaluate_feature_importance(data_file):
    """Evaluate feature importance using Random Forest and plot results."""
    df = pd.read_csv(data_file)
    
    # Separate features and target
    if 'Address' in df.columns:
        X = df.drop(['FLAG', 'Address'], axis=1)
    else:
        X = df.drop('FLAG', axis=1)
    y = df['FLAG']
    
    # Train a Random Forest model
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    
    # Calculate feature importance
    feature_importance = pd.DataFrame({
        'Feature': X.columns,
        'Importance': rf.feature_importances_
    }).sort_values('Importance', ascending=False)
    
    # Plot feature importance
    plt.figure(figsize=(10, 8))
    sns.barplot(x='Importance', y='Feature', data=feature_importance)
    plt.title('Feature Importance')
    plt.tight_layout()
    plt.savefig('feature_importance_optimized.png')
    
    # Calculate model performance
    y_pred = rf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("\nModel Performance with Optimized Features:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    return feature_importance

if __name__ == "__main__":
    input_file = input("Enter path to training dataset (default: trained_dataset.csv): ") or "trained_dataset.csv"
    output_file = input("Enter path for optimized dataset (default: optimized_dataset.csv): ") or "enhanced_trained_dataset.csv"
    
    # Extract essential features
    df_essential = extract_essential_features(input_file, output_file)
    
    # Evaluate feature importance
    if input("Would you like to evaluate feature importance? (y/n): ").lower() == 'y':
        feature_importance = evaluate_feature_importance(output_file)
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))