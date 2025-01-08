from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
import joblib

# Initialize the Flask app
app = Flask(__name__)

# Load the trained model and the scaler
model = tf.keras.models.load_model('model/ids_dnn_model.h5')
scaler = joblib.load('model/scaler.pkl')

@app.route('/analyze_alert', methods=['POST'])
def analyze_alert():
    try:
        # Extract features from the request
        data = request.get_json()
        features = data.get('features')
        print(features)

        if not features:
            return jsonify({'error': 'No features provided'}), 400

        # Convert features to a numpy array
        feature_values = np.array(list(features.values())).reshape(1, -1)

        # Scale the features
        scaled_features = scaler.transform(feature_values)

        # Make a prediction
        prediction = model.predict(scaled_features)
        result = int(prediction[0] > 0.5)  # 1 for attack, 0 for benign

        if result == 1:
            print("\n\nPrediction Result : Attack\n\n")
        elif result == 0:
            print("\n\nPrediction Result : Benign\n\n")
        else :
            print("\n\nPrdiction Result : Unknown\n\n")

        # Return the result
        return jsonify({'prediction': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
