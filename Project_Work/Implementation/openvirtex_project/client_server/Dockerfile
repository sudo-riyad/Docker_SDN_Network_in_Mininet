# Use an official Python runtime as a parent image
FROM ubuntu:18.04

# Set the working directory to /app
WORKDIR /chat

# Copy the current directory contents into the container at /app
COPY . /chat

# Install any needed packages
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    iproute2 \
    curl \
    iperf \
    python3\
    nano\
   
    python3-tk	
# Install needed python packages specified in requirements.txt
#RUN pip3 install -r requirements.txt


