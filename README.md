# Traffic Data Capture Application

This repository contains a traffic data capture application designed to assist data collectors in recording traffic observations. The project includes backend and frontend components, as well as a suite of tests to verify functionality. The goal of this application is to record vehicle data efficiently and scale for use in large-scale traffic studies.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)

## Overview

The Traffic Data Capture Application is built to allow field data collectors to record traffic observations easily, capturing vehicle type, occupancy, location, and timestamps. It includes a frontend for input, a Python server backend, and a database for data storage. The project emphasizes data accuracy, scalability, and maintainability, preparing the application for potential large scale deployment.

## Features

### Core Functionality

- **Login and Logout**: Manages user sessions, allowing secure access to the application.
- **Location Selection**: Provides a list of valid locations for traffic data entry.
- **Traffic Observation Recording**: Allows users to add observations for different vehicle types, recording the location, occupancy, and timestamp.
- **Undo Functionality**: Enables users to reverse recorded observations, ensuring data accuracy.
- **Summary Report**: Generates a summary of the current session’s observations for each vehicle type.

### Additional Functionalities

- **CSV Download**: Generates a downloadable CSV file of traffic summaries by location and date, allowing easy access to organized data.
- **Error Handling**: Validates requests to ensure data integrity, returning error messages for missing or invalid parameters.

### Architecture Proposal

As part of this project, a report was developed to guide the scaling of the application into a SaaS platform. Key points include:

- How I will deal with large numbers of users who are distributed globally.
- How I will ensure the security of each customer’s data and the overall integrity of the
  application.
- How I will deal with users operating in different time zones.
- How I will deal with varying resource demands that will result from customer decisions to
  conduct surveys at particular times of the day or in particular seasons.
- How I will ensure that as the company identifies new features that need to be added these
  can be safely

## Architecture

The backend server is designed with a JSON API to handle requests from the frontend and interacts with a SQL database. The architecture is modular, making it possible to scale individual components as needed. The application’s structure includes:

- **Backend (Python)**: Manages API requests, user sessions, and data operations.
- **Frontend (HTML, CSS, JavaScript)**: Provides an interface for data collectors to input and review data.
- **Database (SQLite)**: Stores user data, session information, and traffic observations, with tables for users, sessions, locations, and traffic data.
- **Testing Suite**: Includes a Jupyter notebook with regression tests to validate functionality.

## Technologies Used

- **Python**: Backend server and API handling
- **SQL**: Data storage and management
- **JSON**: Request and response format for API communication
- **HTML/CSS/JavaScript**: Frontend interface for data entry
- **Jupyter Notebook**: Test suite for functionality verification
