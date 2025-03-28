import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
from datetime import datetime

class OptimizedEthereumFraudDetector:
    def __init__(self, model_path='models\\optimized_ethereum_fraud_model.pkl', 
                 scaler_path='other_opti_features\\optimized_scaler.pkl', 
                 features_path='other_opti_features\\optimized_features.pkl'):
        """Initialize the detector with paths to model files"""
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.features_path = features_path
        self.model = None
        self.scaler = None
        self.features = None
        self.metrics = {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
        
    def preprocess_data(self, data):
        """Preprocess the data by handling missing values and scaling features"""
        # Make a copy to avoid modifying the original
        data = data.copy()
        
        # Remove any columns that start with 'Unnamed'
        unnamed_cols = [col for col in data.columns if col.startswith('Unnamed')]
        if unnamed_cols:
            data = data.drop(columns=unnamed_cols)
        
        # Normalize column names - strip leading/trailing spaces
        data.columns = [col.strip() for col in data.columns]
        
        # Known columns that should be excluded from features
        excluded_columns = ['Index', 'Address', 'FLAG', 'ERC20 most sent token type', 'ERC20_most_rec_token_type']
        
        # Remove any rows with all NaN values
        data = data.dropna(how='all')
        
        # Fill remaining NaN values with appropriate values
        data = data.fillna(0)
        
        # Convert object columns to numeric where possible
        for col in data.columns:
            if data[col].dtype == 'object' and col not in excluded_columns:
                try:
                    data[col] = pd.to_numeric(data[col])
                except:
                    # For columns that can't be converted to numeric, we'll drop them
                    print(f"Dropping non-numeric column: {col}")
                    data = data.drop(columns=[col])
        
        # Save feature columns (excluding target and metadata)
        if self.features is None:
            self.features = [col for col in data.columns if col not in excluded_columns and col != 'FLAG']
        
        return data
    
    def train(self, data_path, test_size=0.2, optimize=True):
        """Train the Random Forest model on the dataset"""
        #print(f"Loading data from {data_path}...")
        df = pd.read_csv(data_path)
        
        # Preprocess the data
        df = self.preprocess_data(df)
        
        # Load additional data from analyzed_wallet_datas.csv if it exists
        analyzed_data_path = "csv_files\\analyzed_wallet_datas.csv"
        if os.path.exists(analyzed_data_path):
            #print(f"Loading additional data from {analyzed_data_path}...")
            additional_data = pd.read_csv(analyzed_data_path)
            additional_data = self.preprocess_data(additional_data)
            
            # Ensure the additional data has the required columns
            missing_columns = [col for col in self.features if col not in additional_data.columns]
            for col in missing_columns:
                additional_data[col] = 0  # Add missing columns with default values
            
            # Append the additional data to the main dataset
            df = pd.concat([df, additional_data], ignore_index=True)
            #print(f"Additional data from {analyzed_data_path} has been added to the training dataset.")
        else:
            pass
            #print(f"No additional data found at {analyzed_data_path}. Proceeding with the main dataset.")
        
        # Split features and target
        X = df[self.features]
        y = df['FLAG']
        
        # Create train/test split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        
        # Scale the features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Initialize the model with optimized parameters
        if optimize:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42
            )
        else:
            # Use default parameters
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Train the model
        #print("Training the model...")
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate on test set
        y_pred = self.model.predict(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        # Store metrics
        self.metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        #print(f"Model Performance:")
        #print(f"Accuracy: {accuracy:.4f}")
        #print(f"Precision: {precision:.4f}")
        #print(f"Recall: {recall:.4f}")
        #print(f"F1 Score: {f1:.4f}")
        
        # Display confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('Actual Label')
        plt.xlabel('Predicted Label')
        
        # Create directories if they don't exist
        os.makedirs('images', exist_ok=True)
        plt.savefig('images\\optimized_confusion_matrix.png')
        
        # Print classification report
        #print("\nClassification Report:")
        #print(classification_report(y_test, y_pred))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'Feature': self.features,
            'Importance': self.model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        #print("\nTop 10 Most Important Features:")
        #print(feature_importance.head(10))
        
        # Save the model and related files
        self.save_model()
        
        # Plot feature importance
        plt.figure(figsize=(12, 10))
        sns.barplot(x='Importance', y='Feature', data=feature_importance.head(20))
        plt.title('Top 20 Feature Importance')
        plt.tight_layout()
        plt.savefig('images\\optimized_feature_importance.png')
        
        return self.metrics
    
    def save_model(self):
        """Save the model, scaler, and features to disk"""
        if self.model is not None and self.scaler is not None and self.features is not None:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.features, self.features_path)
            #print(f"Model saved to {self.model_path}")
            #print(f"Scaler saved to {self.scaler_path}")
            #print(f"Features saved to {self.features_path}")
            
    def load_model(self):
        """Load a pre-trained model, scaler, and features"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path) and os.path.exists(self.features_path):
                #print(f"Loading model from {self.model_path}")
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.features = joblib.load(self.features_path)
                #print("Model, scaler, and features loaded successfully")
                return True
            else:
                missing_files = []
                if not os.path.exists(self.model_path):
                    missing_files.append(self.model_path)
                if not os.path.exists(self.scaler_path):
                    missing_files.append(self.scaler_path)
                if not os.path.exists(self.features_path):
                    missing_files.append(self.features_path)
                #print(f"Missing files: {', '.join(missing_files)}")
                return False
        except Exception as e:
            #print(f"Error loading model: {str(e)}")
            return False
    
    def predict_risk(self, wallet_data, threshold=0.5):
        """Predict risk score for a wallet address"""
        # Ensure model is loaded
        if self.model is None:
            loaded = self.load_model()
            if not loaded:
                raise Exception("No model loaded or trained.")
        
        # Convert to DataFrame if it's a dictionary
        if isinstance(wallet_data, dict):
            wallet_data = pd.DataFrame([wallet_data])
        
        # Preprocess data similar to training data
        wallet_data = wallet_data.copy()
        
        # Extract address for reporting
        address = wallet_data['Address'].iloc[0] if 'Address' in wallet_data.columns else "Unknown"
        
        # Ensure all required features exist in the data
        for feature in self.features:
            if feature not in wallet_data.columns:
                # Look for column with different spacing
                feature_stripped = feature.strip()
                possible_matches = [col for col in wallet_data.columns if col.strip() == feature_stripped]
                
                if possible_matches:
                    wallet_data[feature] = wallet_data[possible_matches[0]]
                else:
                    print(f"Column {feature} not found in input data. Creating with default values.")
                    wallet_data[feature] = 0
        
        # Keep only the features used during training
        wallet_features = wallet_data[self.features].copy()
        
        # Scale the features
        wallet_features_scaled = self.scaler.transform(wallet_features)
        
        # Get prediction probability
        risk_prob = self.model.predict_proba(wallet_features_scaled)[0, 1]
        
        # Make binary prediction
        risk_label = 1 if risk_prob >= threshold else 0
        
        result = {
            'address': address,
            'risk_score': risk_prob,
            'risk_label': risk_label,
            'prediction_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'top_indicators': {}
        }
        
        # Get feature contributions (top 5 most important for this prediction)
        feature_importance = []
        for i, feature in enumerate(self.features):
            value = wallet_features.iloc[0, i]
            importance = self.model.feature_importances_[i]
            feature_importance.append((feature, value, importance * value))
        
        # Sort by contribution magnitude
        feature_importance.sort(key=lambda x: abs(x[2]), reverse=True)
        
        # Add top 5 to results
        for feature, value, contribution in feature_importance[:5]:
            result['top_indicators'][feature] = {
                'value': value,
                'contribution': contribution
            }
        
        return result
    
    def evaluate_model(self, data_path, test_size=0.2):
        """Evaluate the model on test data and return performance metrics"""
        # Load data
        df = pd.read_csv(data_path)
        df = self.preprocess_data(df)
        
        # Split features and target
        X = df[self.features]
        y = df['FLAG']
        
        # Create train/test split
        _, X_test, _, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        
        # Scale features
        X_test_scaled = self.scaler.transform(X_test)
        
        # Generate predictions
        y_pred = self.model.predict(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        #print(f"Model Evaluation:")
        #print(f"Accuracy: {accuracy:.4f}")
        #print(f"Precision: {precision:.4f}")
        #print(f"Recall: {recall:.4f}")
        #print(f"F1 Score: {f1:.4f}")
        
        return metrics

    def retrain_and_compare(self, data_path="csv_files\\enhanced_trained_dataset.csv", test_size=0.2):
        """Retrain the model using new data and automatically keep the better performing model"""
        #print("Retraining model with new data...")
        
        # First, check if we have a model to compare against
        original_model_exists = os.path.exists(self.model_path)
        
        if original_model_exists:
            # Save the original model objects
            original_model = None
            original_scaler = None
            original_features = None
            original_metrics = None
            
            # Load the original model if it exists
            if self.load_model():
                original_model = self.model
                original_scaler = self.scaler
                original_features = self.features
                
                # Evaluate the original model
               # print("Evaluating the original model...")
                original_metrics = self.evaluate_model(data_path, test_size)
            
            # Clear the current model to train a new one
            self.model = None
            self.scaler = None
        
        # Create a temporary path for the new model
        temp_model_path = "models\\temp_optimized_ethereum_fraud_model.pkl"
        temp_scaler_path = "other_opti_features\\temp_optimized_scaler.pkl"
        temp_features_path = "other_opti_features\\temp_optimized_features.pkl"
        
        # Store the original paths
        original_model_path = self.model_path
        original_scaler_path = self.scaler_path
        original_features_path = self.features_path
        
        # Set temporary paths
        self.model_path = temp_model_path
        self.scaler_path = temp_scaler_path
        self.features_path = temp_features_path
        
        # Train a new model
        #print("Training a new model...")
        new_metrics = self.train(data_path, test_size=test_size)
        
        if original_model_exists and original_metrics:
            # Compare metrics
            #print("\nModel Comparison:")
            #print("Metric    | Original | New Model | Difference")
            #print("-" * 50)
            
            # Calculate overall improvement
            improvements = []
            for metric in ['accuracy', 'precision', 'recall', 'f1']:
                diff = new_metrics[metric] - original_metrics[metric]
                improvements.append(diff)
                #print(f"{metric.title():<9} | {original_metrics[metric]:.4f} | {new_metrics[metric]:.4f} | {diff:+.4f}")
            
            # Automatically decide based on average improvement
            avg_improvement = sum(improvements) / len(improvements)
            keep_new = avg_improvement > 0
            
            if keep_new:
                # Replace the original model with the new one
                #print("\nNew model shows better performance. Automatically updating...")
                if os.path.exists(temp_model_path):
                    os.replace(temp_model_path, original_model_path)
                if os.path.exists(temp_scaler_path):
                    os.replace(temp_scaler_path, original_scaler_path)
                if os.path.exists(temp_features_path):
                    os.replace(temp_features_path, original_features_path)
                
                # Restore original paths
                self.model_path = original_model_path
                self.scaler_path = original_scaler_path
                self.features_path = original_features_path
                
                #print("New model saved successfully!")
                #print(f"Average improvement across metrics: {avg_improvement:.4f}")
            else:
                # Restore original model and paths
                #print("\nOriginal model performs better. Keeping original model...")
                self.model = original_model
                self.scaler = original_scaler
                self.features = original_features
                
                self.model_path = original_model_path
                self.scaler_path = original_scaler_path
                self.features_path = original_features_path
                
                # Clean up temporary files
                for temp_file in [temp_model_path, temp_scaler_path, temp_features_path]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                #print(f"Average difference in metrics: {avg_improvement:.4f}")
        else:
            # If no original model exists, simply save the new one
            #print("No original model found. Saving new model...")
            self.model_path = original_model_path
            self.scaler_path = original_scaler_path
            self.features_path = original_features_path
            self.save_model()
        
        return new_metrics

detector = OptimizedEthereumFraudDetector()
# Call the train method on the instance
detector.train("ML\\csv_files\\enhanced_trained_dataset.csv")