First clone the repo:
# Backend:
    cd web3_task /
    pip install -r requirements.txt
    python manage.py runserver

this will start the Django server on **http://127.0.0.1:8000/**

# Authentication using metamask wallet and web3 :

<img width="840" alt="Screenshot 2023-08-28 at 9 41 38 AM" src="https://github.com/mushahid54/web3_py/assets/7305532/3eaeeba7-4dbb-4b59-9c51-df978911ce90">

Make sure you have metamask wallent extension in your browser: once logged in you will see like this

<img width="1091" alt="demo" src="https://github.com/mushahid54/web3_py/assets/7305532/5be572ff-7c07-4c06-ac1b-2e029afe36c5">

## API endpoint for swap events using address (while fethcing the transaction and logs events)

    http://127.0.0.1:8000/api/v1/decode_swap_token/

<img width="945" alt="Screenshot 2023-08-28 at 9 32 51 AM" src="https://github.com/mushahid54/web3_py/assets/7305532/aae90826-fd0e-4492-909b-5a52dd5ab777">

Note : Use python >=3.9
