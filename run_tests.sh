python3.11 --version
echo "start running tests on request"
python3.11 -m automower_ble.request
echo "start running tests on response"
python3.11 -m automower_ble.response
