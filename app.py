# app.py
from flask import Flask, render_template, request, jsonify
import joblib
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Load the trained model
try:
    model_data = joblib.load('url_anomaly_model.joblib')
    model = model_data['model']
    scaler = model_data['scaler']
    label_encoder = model_data['label_encoder']
except:
    print("Error: Could not load the model. Make sure 'url_anomaly_model.joblib' exists.")
    exit()

def extract_url_features(url):
    try:
        features = {
            'count_dot': url.count('.'),
            'count_dir': urlparse(url).path.count('/'),
            'count_embed': urlparse(url).path.count('//'),
            'count_http': url.count('http'),
            'count_percent': url.count('%'),
            'count_ques': url.count('?'),
            'count_hyphen': url.count('-'),
            'count_equal': url.count('='),
            'url_length': len(str(url)),
            'hostname_length': len(urlparse(url).netloc),
            'count_digits': sum(c.isdigit() for c in url),
            'count_letters': sum(c.isalpha() for c in url),
            'count_special': len(re.sub(r'[a-zA-Z0-9\s]', '', url)),
            'is_encoded': int('%' in url.lower()),
            'unusual_char_ratio': len(re.sub(r'[a-zA-Z0-9\s\-._]', '', url)) / len(url) if len(url) > 0 else 0
        }
        
        suspicious_patterns = {
            'error': 30, 'select': 50, 'union': 35, 'insert': 50, 'drop': 50,
            'update': 50, 'delete': 50, 'script': 40, 'alert': 30, 'eval': 35,
            'javascript': 40, 'document': 30, 'cookie': 25, 'xss': 45,
            'sql': 40, 'injection': 40, 'hack': 35, 'admin': 30
        }
        
        features['suspicious_score'] = sum(score 
            for word, score in suspicious_patterns.items() 
            if word in url.lower())
            
        return features
    except:
        return dict.fromkeys(features.keys(), 0)

def extract_content_features(content):
    if not content:
        return dict.fromkeys(['content_length', 'content_digit_ratio', 
                            'content_special_ratio', 'content_suspicious_score'], 0)
    
    try:
        content = str(content)
        total_len = len(content)
        
        features = {
            'content_length': total_len,
            'content_digit_ratio': sum(c.isdigit() for c in content) / total_len if total_len > 0 else 0,
            'content_special_ratio': len(re.sub(r'[a-zA-Z0-9\s]', '', content)) / total_len if total_len > 0 else 0,
        }
        
        suspicious_patterns = {
            'script': 40, 'alert': 35, 'eval': 40, 'function': 30,
            'document': 30, 'cookie': 25, 'window': 25, 'iframe': 35,
            'src': 25, 'href': 25, 'onload': 30, 'onerror': 30
        }
        
        features['content_suspicious_score'] = sum(score 
            for word, score in suspicious_patterns.items() 
            if word in content.lower())
            
        return features
    except:
        return dict.fromkeys(features.keys(), 0)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '')
        method = data.get('method', 'GET')
        content = data.get('content', '')

        # Extract features
        url_features = extract_url_features(url)
        content_features = extract_content_features(content)
        
        # Combine features
        features = {}
        features.update(url_features)
        features.update(content_features)
        
        # Encode method
        try:
            method_encoded = label_encoder.transform([method])[0]
        except:
            method_encoded = 0
        
        features['method_encoded'] = method_encoded
        
        # Convert to DataFrame
        import pandas as pd
        input_df = pd.DataFrame([features])
        
        # Scale features
        input_scaled = scaler.transform(input_df)
        
        # Make prediction
        prediction = model.predict(input_scaled)[0]
        prediction_prob = model.predict_proba(input_scaled)[0]
        
        return jsonify({
            'prediction': 'Anomalous' if prediction else 'Normal',
            'confidence': float(max(prediction_prob) * 100),
            'features': {
                'suspicious_score': features['suspicious_score'],
                'content_suspicious_score': features['content_suspicious_score'],
                'unusual_char_ratio': features['unusual_char_ratio']
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
    