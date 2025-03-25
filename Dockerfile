# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the necessary packages directly
RUN pip install --no-cache-dir Flask Flask-Login google-generativeai requests pymongo bcrypt

# Make port 5000 available to the world outside this container
EXPOSE 8000

# Define environment variable
ENV FLASK_APP app.py

# Run app.py when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]
