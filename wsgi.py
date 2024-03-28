from app import create_app

# Create Flask application
app = create_app()

# This is required for Gunicorn to work correctly
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
