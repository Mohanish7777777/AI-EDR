FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy the application files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir flask flask-login google-generativeai pymongo bcrypt requests

# Expose the port the app runs on
EXPOSE 5000

# Define environment variable
 ENV FLASK_APP app.py
 
 # Run app.py when the container launches
 CMD ["flask", "run", "--host=0.0.0.0"]
