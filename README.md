livehttpx 0.1.0

  a very fast live URL testing tool in Python

Overview
  livehttpx is a high-performance, lightweight, and reliable live URL testing tool designed entirely in Python. It allows users to quickly and efficiently verify the status and responsiveness of multiple URLs.
  Whether you're a security researcher, a webmaster, or an enthusiast, livehttpx is here to simplify testing for live URLs in bulk.

Features

  🚀 Fast and Reliable: Parses and checks thousands of URLs efficiently.
  🌐 Real-Time Insights: Provides HTTP status codes and detailed live URL responses.
  🔧 Python-Powered: Built entirely in Python for easy customization.
  🔒 Secure Processing: Ensures secure and error-tolerant URL validation.

Installation

  To use this tool, ensure you have Python (version 3.7+) installed on your system.

# Clone the repository
git clone https://github.com/Juru-Christopher/livehttpx0.1.0.git

# Navigate to the directory
cd livehttpx0.1.0

# Install the required dependencies
pip install -r requirements.txt

Usage
Once you have the tool installed, you can use the following commands to get started. Simply provide your list of URLs, and livehttpx will check their status and responsiveness.
bash

python livehttpx.py -i <input_file> -o <output_file>

Example
python livehttpx.py -i urls.txt -o results.txt
  Input File (-i): A text file containing a list of URLs (one per line).
  Output File (-o): A text file where the results will be saved.

Output
After execution, the tool generates an output file containing the URLs’ statuses. For example:
plaintext

200 - https://www.github.com
404 - https://www.example.com/notfound
503 - https://www.downforeveryone.com

Contributing
Contributions to livehttpx are welcome!
  Fork the repository.
  Create a feature branch (git checkout -b my-feature).
  Commit your changes with clear messages (git commit -m "Add feature").
  Push to your fork (git push origin my-feature).
  Create a Pull Request.

License
  This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
  Created by gc137001e
  Inspired by the need for fast and reliable bulk URL status testing.
