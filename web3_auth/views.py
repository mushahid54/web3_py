import json
from multiprocessing import pool
import requests
import web3

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from rest_framework import permissions, viewsets, status, generics, mixins, exceptions
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from moralis import evm_api
from rest_framework.response import Response
from rest_framework.views import APIView
from web3 import Web3, EthereumTesterProvider
from web3_auth.mixin import CustomMetaDataMixin
from web3.logs import DISCARD


API_KEY = 'NtznkT0fM89IIuoHGXwCgDburQUsD8aAdOaydhsHk73RDYfnI2BWGWd0f7X7cC5z'
if API_KEY == 'WEB3_API_KEY_HERE':
    print("API key is not set")
    raise SystemExit

# from eth_account.messages import encode_defunct
# from django.shortcuts import render
# from django.http import HttpResponse
# from eth_account import Account
# from django.shortcuts import render
# from django.http import HttpResponse
# from web3 import Web3
# from web3_auth.models import User
#
#
# def login(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         public_key = request.POST.get('public_key')
#         user = User.objects.filter(username=username, public_key=public_key).first()
#         if user is None:
#             return HttpResponse("Invalid username or password")
#         else:
#             return HttpResponse("Logged in successfully")
#     return render(request, 'registration/login.html')
#
#
# def verify_signature(address, signature, message):
#     message_hash = encode_defunct(text=message)
#     try:
#         # Recover the public key from the signature
#         public_key = Account.recover_message(message_hash, signature=signature)
#         # Convert the public key to an Ethereum address
#         recovered_address = Web3.toChecksumAddress(Account.from_key(public_key).address)
#         # Compare the recovered address with the provided address
#         if address == recovered_address:
#             return True
#     except:
#         pass
#     return False
#
#
# from django.views.decorators.csrf import csrf_exempt
# from django.http import JsonResponse
#
# @csrf_exempt
# def authenticate(request):
#     if request.method == 'POST':
#         # Get the address, signature, and message from the request body
#         address = request.data.get('address')
#         signature = request.POST.get('signature')
#         message = request.POST.get('message')
#         # Verify the signature
#         if verify_signature(address, signature, message):
#             # If the signature is valid, log in the user
#             user = User.objects.get_or_create(address=address)
#             login(request, user)
#             return JsonResponse({'status': 'success'})
#
#     return JsonResponse({'status': 'error'})
#
#
#
#
#
#


# def login(request, user):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         public_key = request.POST.get('public_key')
#         user = User.objects.filter(username=username, public_key=public_key).first()
#         if user is None:
#             return HttpResponse("Invalid username or password")
#         else:
#             return HttpResponse("Logged in successfully")
#     return render(request, 'login_old.html')


def moralis_auth(request):
    return render(request, 'login_old.html', {})

def my_profile(request):
    return render(request, 'profile.html', {})

def request_message(request):
    data = json.loads(request.body)
    print(data)

    REQUEST_URL = 'https://authapi.moralis.io/challenge/request/evm'
    request_object = {
      "domain": "defi.finance",
      "chainId": 1,
      "address": data['address'],
      "statement": "Please confirm",
      "uri": "https://defi.finance/",
      "expirationTime": "2024-01-01T00:00:00.000Z",
      "notBefore": "2020-01-01T00:00:00.000Z",
      "timeout": 60
    }
    x = requests.post(
        REQUEST_URL,
        json=request_object,
        headers={'X-API-KEY': API_KEY})

    return JsonResponse(json.loads(x.text))


def verify_message(request):
    data = json.loads(request.body)
    print(data)

    REQUEST_URL = 'https://authapi.moralis.io/challenge/verify/evm'
    x = requests.post(
        REQUEST_URL,
        json=data,
        headers={'X-API-KEY': API_KEY})
    print(json.loads(x.text))
    print(x.status_code)
    if x.status_code == 201:
        # user can authenticate
        eth_address=json.loads(x.text).get('address')
        print("eth address", eth_address)
        try:
            user = User.objects.get(username=eth_address)
        except User.DoesNotExist:
            user = User(username=eth_address)
            user.is_staff = False
            user.is_superuser = False
            user.save()
        if user is not None:
            params = {"address": eth_address,
                        "chain": "eth"
                        }
            if user.is_active:
                result = evm_api.token.get_wallet_token_transfers(api_key=API_KEY, params=params)
                print(result)

                login(request, user)
                request.session['auth_info'] = data
                request.session['verified_data'] = json.loads(x.text)
                return JsonResponse({'user': user.username})
            else:
                return JsonResponse({'error': 'account disabled'})
    else:
        return JsonResponse(json.loads(x.text))

class Web3LearningAPIViews(CustomMetaDataMixin, generics.ListAPIView):

    def get(self, request, format=None):
        latest_block_list = []
        transfer_details_list = []
        infura_url = "https://mainnet.infura.io/v3/075829e0a6ab486680b1f0970943c3a2"
        w3 = Web3(Web3.HTTPProvider(infura_url))
        check_connection = w3.isConnected()
        abi_json = json.loads('[{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"address","name":"minter_","type":"address"},{"internalType":"uint256","name":"mintingAllowedAfter_","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegator","type":"address"},{"indexed":true,"internalType":"address","name":"fromDelegate","type":"address"},{"indexed":true,"internalType":"address","name":"toDelegate","type":"address"}],"name":"DelegateChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegate","type":"address"},{"indexed":false,"internalType":"uint256","name":"previousBalance","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newBalance","type":"uint256"}],"name":"DelegateVotesChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"minter","type":"address"},{"indexed":false,"internalType":"address","name":"newMinter","type":"address"}],"name":"MinterChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":true,"inputs":[],"name":"DELEGATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"DOMAIN_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"PERMIT_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint32","name":"","type":"uint32"}],"name":"checkpoints","outputs":[{"internalType":"uint32","name":"fromBlock","type":"uint32"},{"internalType":"uint96","name":"votes","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"delegatee","type":"address"}],"name":"delegate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"delegatee","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"expiry","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"delegateBySig","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"delegates","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"getCurrentVotes","outputs":[{"internalType":"uint96","name":"","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint256","name":"blockNumber","type":"uint256"}],"name":"getPriorVotes","outputs":[{"internalType":"uint96","name":"","type":"uint96"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"minimumTimeBetweenMints","outputs":[{"internalType":"uint32","name":"","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"mintCap","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"minter","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"mintingAllowedAfter","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"numCheckpoints","outputs":[{"internalType":"uint32","name":"","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"minter_","type":"address"}],"name":"setMinter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"src","type":"address"},{"internalType":"address","name":"dst","type":"address"},{"internalType":"uint256","name":"rawAmount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]')
        address_eth_currency = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"
        if check_connection:
            checksum_address = Web3.toChecksumAddress(address_eth_currency)
            contract = w3.eth.contract(address=checksum_address,abi=abi_json)
            total_supply = contract.functions.totalSupply().call()
            contract_name = contract.functions.name().call()
            contract_symbol = contract.functions.symbol().call()
            block_number = w3.eth.blockNumber
            balance = w3.eth.getBalance(address_eth_currency)
            convert_to_eth = w3.fromWei(balance, 'ether')
            transaction_count_from_account = w3.eth.getTransactionCount(checksum_address)
            # balance = contract.functions.balanceOf.call()
            latest_block  = w3.eth.getBlock(block_number).transactions[:10]

            for trx_hash in latest_block:
                convert_to_dict = dict(w3.eth.getTransaction(trx_hash.hex()))
                trx_hash="0x34134dcb3f2b7fe178711c488a3a7d2906faa039d05176adffff923f50d07b4f"
                tx_receipt = dict(w3.eth.getTransactionReceipt(trx_hash))
                sender = tx_receipt["from"]
                transfers = contract.events.Transfer().processReceipt(tx_receipt,errors=DISCARD)
                for element in transfers:
                    args = element["args"]
                    # if args['from'] == sender:
                    #     direction = "SELLS"
                    # elif args['to'] == sender:
                    #     direction = "BUYS"
                    # else:
                    #     continue
                    token_address = element["address"]
                    amount = args["amount"]

                    token_contract = w3.eth.contract(address=token_address, abi=abi_json)
                    token_symbol = token_contract.functions.symbol().call()
                    token_decimals = token_contract.functions.decimals().call()

                    transfer_details = {"Sender_Wallet": sender, "values": (amount/10)*token_decimals,"token_symbol": token_symbol}
                    transfer_details_list.append(transfer_details)

                tx_info = {
                    "From": convert_to_dict.get('from', None),
                    "To": convert_to_dict.get('to', None),
                    "GasUsed": tx_receipt.get('gasUsed',None),
                    "MaxFeePerGas": convert_to_dict.get('maxFeePerGas',None),
                    "Gas": convert_to_dict.get('gas',None),
                    "GasPrice": convert_to_dict.get('gasPrice',None),
                    "Value": convert_to_dict.get('value',None),
                }
                latest_block_list.append(tx_info)

            return Response({"dict_info": {
                            "total_transaction": transaction_count_from_account,
                            "total_supply": total_supply,"name": contract_name, "block_number": block_number,
                            "contract_symbol": contract_symbol, "balance_eth": convert_to_eth,
                            "latest_tx_info": latest_block_list,
                            "transfer_details": transfer_details_list,
                            }}, status=status.HTTP_200_OK)


class TransferdetailsAPIViews(CustomMetaDataMixin, generics.ListAPIView):

    def get(self, request, format=None):
        latest_block_list = []
        transfer_details_list = []
        infura_url = "https://mainnet.infura.io/v3/075829e0a6ab486680b1f0970943c3a2"
        w3 = Web3(Web3.HTTPProvider(infura_url))
        check_connection = w3.isConnected()
        abi_json = json.loads('[{"type":"constructor","stateMutability":"nonpayable","payable":false,"inputs":[]},{"type":"event","name":"Approval","inputs":[{"type":"address","name":"owner","internalType":"address","indexed":true},{"type":"address","name":"spender","internalType":"address","indexed":true},{"type":"uint256","name":"value","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Burn","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1","internalType":"uint256","indexed":false},{"type":"address","name":"to","internalType":"address","indexed":true}],"anonymous":false},{"type":"event","name":"Mint","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Swap","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0In","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1In","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount0Out","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1Out","internalType":"uint256","indexed":false},{"type":"address","name":"to","internalType":"address","indexed":true}],"anonymous":false},{"type":"event","name":"Sync","inputs":[{"type":"uint112","name":"reserve0","internalType":"uint112","indexed":false},{"type":"uint112","name":"reserve1","internalType":"uint112","indexed":false}],"anonymous":false},{"type":"event","name":"Transfer","inputs":[{"type":"address","name":"from","internalType":"address","indexed":true},{"type":"address","name":"to","internalType":"address","indexed":true},{"type":"uint256","name":"value","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"bytes32","name":"","internalType":"bytes32"}],"name":"DOMAIN_SEPARATOR","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"MINIMUM_LIQUIDITY","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"bytes32","name":"","internalType":"bytes32"}],"name":"PERMIT_TYPEHASH","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"allowance","inputs":[{"type":"address","name":"","internalType":"address"},{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"approve","inputs":[{"type":"address","name":"spender","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"balanceOf","inputs":[{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"uint256","name":"amount0","internalType":"uint256"},{"type":"uint256","name":"amount1","internalType":"uint256"}],"name":"burn","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint8","name":"","internalType":"uint8"}],"name":"decimals","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"factory","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint112","name":"_reserve0","internalType":"uint112"},{"type":"uint112","name":"_reserve1","internalType":"uint112"},{"type":"uint32","name":"_blockTimestampLast","internalType":"uint32"}],"name":"getReserves","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"initialize","inputs":[{"type":"address","name":"_token0","internalType":"address"},{"type":"address","name":"_token1","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"kLast","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"uint256","name":"liquidity","internalType":"uint256"}],"name":"mint","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"string","name":"","internalType":"string"}],"name":"name","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"nonces","inputs":[{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"permit","inputs":[{"type":"address","name":"owner","internalType":"address"},{"type":"address","name":"spender","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"},{"type":"uint256","name":"deadline","internalType":"uint256"},{"type":"uint8","name":"v","internalType":"uint8"},{"type":"bytes32","name":"r","internalType":"bytes32"},{"type":"bytes32","name":"s","internalType":"bytes32"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"price0CumulativeLast","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"price1CumulativeLast","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"skim","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"swap","inputs":[{"type":"uint256","name":"amount0Out","internalType":"uint256"},{"type":"uint256","name":"amount1Out","internalType":"uint256"},{"type":"address","name":"to","internalType":"address"},{"type":"bytes","name":"data","internalType":"bytes"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"string","name":"","internalType":"string"}],"name":"symbol","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"sync","inputs":[],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"token0","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"token1","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"totalSupply","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"transfer","inputs":[{"type":"address","name":"to","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"transferFrom","inputs":[{"type":"address","name":"from","internalType":"address"},{"type":"address","name":"to","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false}]')
        address_eth_currency = "0x39cC0E14795A8e6e9D02A21091b81FE0d61D82f9"
        if check_connection:
            checksum_address = Web3.toChecksumAddress(address_eth_currency)
            contract = w3.eth.contract(address=checksum_address,abi=abi_json)
            # total_supply = contract.functions.totalSupply().call()
            # contract_name = contract.functions.name().call()
            # contract_symbol = contract.functions.symbol().call()
            block_number = w3.eth.blockNumber
            # transaction_count_from_account = w3.eth.getTransactionCount(checksum_address)
            # balance = contract.functions.balanceOf.call()
            latest_block  = w3.eth.getBlock(block_number).transactions[:10]

            for trx_hash in latest_block:
                tx_receipt = dict(w3.eth.getTransactionReceipt(trx_hash))
                sender = tx_receipt["from"]
                #Swap transactions of the QuickSwap USDC/WETH pool occurring over the last 10 blocks.
                transfers = contract.events.Transfer().processReceipt(tx_receipt,errors=DISCARD)
                for element in transfers:
                    args = element["args"]
                    # if args['from'] == sender:
                    #     direction = "SELLS"
                    # elif args['to'] == sender:
                    #     direction = "BUYS"
                    # else:
                    #     continue
                    token_address = element["address"]
                    amount = args["value"]

                    token_contract = w3.eth.contract(address=token_address, abi=abi_json)
                    token_symbol = token_contract.functions.symbol().call()
                    token_decimals = token_contract.functions.decimals().call()

                    transfer_details = {"Sender_Wallet": sender, "values": (amount/10)*token_decimals,"token_symbol": token_symbol}
                    transfer_details_list.append(transfer_details)


            return Response({"dict_info": {
                              "block_number": block_number,
                            "transfer_details": transfer_details_list,
                            }}, status=status.HTTP_200_OK)

import os
import time
from functools import lru_cache

from web3 import HTTPProvider, Web3

from eth_defi.abi import get_contract
from eth_defi.uniswap_v2 import analysis
# from eth_defi.chain import install_chain_middleware
from eth_defi.event_reader.filter import Filter
from eth_defi.event_reader.logresult import *
from eth_defi.event_reader.reader import read_events
from eth_defi.uniswap_v2.pair import fetch_pair_details, PairDetails

class UniSwapAllPairs(CustomMetaDataMixin, generics.ListAPIView):

    def get(self, request, format=None):
        transfer_details_list = []
        infura_url = "https://mainnet.infura.io/v3/075829e0a6ab486680b1f0970943c3a2"
        abi_json = json.loads('[{"type":"constructor","stateMutability":"nonpayable","payable":false,"inputs":[]},{"type":"event","name":"Approval","inputs":[{"type":"address","name":"owner","internalType":"address","indexed":true},{"type":"address","name":"spender","internalType":"address","indexed":true},{"type":"uint256","name":"value","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Burn","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1","internalType":"uint256","indexed":false},{"type":"address","name":"to","internalType":"address","indexed":true}],"anonymous":false},{"type":"event","name":"Mint","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Swap","inputs":[{"type":"address","name":"sender","internalType":"address","indexed":true},{"type":"uint256","name":"amount0In","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1In","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount0Out","internalType":"uint256","indexed":false},{"type":"uint256","name":"amount1Out","internalType":"uint256","indexed":false},{"type":"address","name":"to","internalType":"address","indexed":true}],"anonymous":false},{"type":"event","name":"Sync","inputs":[{"type":"uint112","name":"reserve0","internalType":"uint112","indexed":false},{"type":"uint112","name":"reserve1","internalType":"uint112","indexed":false}],"anonymous":false},{"type":"event","name":"Transfer","inputs":[{"type":"address","name":"from","internalType":"address","indexed":true},{"type":"address","name":"to","internalType":"address","indexed":true},{"type":"uint256","name":"value","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"bytes32","name":"","internalType":"bytes32"}],"name":"DOMAIN_SEPARATOR","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"MINIMUM_LIQUIDITY","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"bytes32","name":"","internalType":"bytes32"}],"name":"PERMIT_TYPEHASH","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"allowance","inputs":[{"type":"address","name":"","internalType":"address"},{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"approve","inputs":[{"type":"address","name":"spender","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"balanceOf","inputs":[{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"uint256","name":"amount0","internalType":"uint256"},{"type":"uint256","name":"amount1","internalType":"uint256"}],"name":"burn","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint8","name":"","internalType":"uint8"}],"name":"decimals","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"factory","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint112","name":"_reserve0","internalType":"uint112"},{"type":"uint112","name":"_reserve1","internalType":"uint112"},{"type":"uint32","name":"_blockTimestampLast","internalType":"uint32"}],"name":"getReserves","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"initialize","inputs":[{"type":"address","name":"_token0","internalType":"address"},{"type":"address","name":"_token1","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"kLast","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"uint256","name":"liquidity","internalType":"uint256"}],"name":"mint","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"string","name":"","internalType":"string"}],"name":"name","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"nonces","inputs":[{"type":"address","name":"","internalType":"address"}],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"permit","inputs":[{"type":"address","name":"owner","internalType":"address"},{"type":"address","name":"spender","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"},{"type":"uint256","name":"deadline","internalType":"uint256"},{"type":"uint8","name":"v","internalType":"uint8"},{"type":"bytes32","name":"r","internalType":"bytes32"},{"type":"bytes32","name":"s","internalType":"bytes32"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"price0CumulativeLast","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"price1CumulativeLast","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"skim","inputs":[{"type":"address","name":"to","internalType":"address"}],"constant":false},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"swap","inputs":[{"type":"uint256","name":"amount0Out","internalType":"uint256"},{"type":"uint256","name":"amount1Out","internalType":"uint256"},{"type":"address","name":"to","internalType":"address"},{"type":"bytes","name":"data","internalType":"bytes"}],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"string","name":"","internalType":"string"}],"name":"symbol","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[],"name":"sync","inputs":[],"constant":false},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"token0","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"address","name":"","internalType":"address"}],"name":"token1","inputs":[],"constant":true},{"type":"function","stateMutability":"view","payable":false,"outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"totalSupply","inputs":[],"constant":true},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"transfer","inputs":[{"type":"address","name":"to","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false},{"type":"function","stateMutability":"nonpayable","payable":false,"outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"transferFrom","inputs":[{"type":"address","name":"from","internalType":"address"},{"type":"address","name":"to","internalType":"address"},{"type":"uint256","name":"value","internalType":"uint256"}],"constant":false}]')
        w3 = Web3(Web3.HTTPProvider(infura_url))
        check_connection = w3.isConnected()
        # Pair = get_contract(web3, "IUniswapV2ERC20.json")

        address_eth_currency = "0x39cC0E14795A8e6e9D02A21091b81FE0d61D82f9"
        if check_connection:
            checksum_address = Web3.toChecksumAddress(address_eth_currency)
            contract = w3.eth.contract(address=checksum_address, abi=abi_json)
            event_filter = w3.eth.filter({'topics': [contract.events.Swap.address]})
            # filter = Filter.create_filter(address=None, event_types=[w3.events.Swap])

        return Response({"dict_info": {
                            "transfer_details": "latest_block_list",
                            }}, status=status.HTTP_200_OK)


# from web3 import Web3
# from datetime import datetime
# import requests
# from hexbytes import HexBytes
#
# # Web3 connection
# w3 = Web3('your connection')
#
# endblock   = w3.eth.blockNumber
# startblock = endblock - 1000
#
# # contract address (Quickswap USDC/WETH pool)
# address = '0x853ee4b2a13f8a742d64c8f088be7ba2131f670d'
#
# # APIKey
# APIKey = 'your API Key'
#
# # Topic for Log filter
# topic0 = '0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822' # ---> This is the topic identifying the swap function of the pool contract
# topic1 = '0x000000000000000000000000a5e0829caced8ffdd4de3c43696c57f7d7a678ff' # ---> This is the topic identifying the swap router
#
# # Get all Logs which meet the topic criteria and the pool contract address
# Logs = 'https://api.polygonscan.com/api?module=logs&action=getLogs&fromBlock='+str(startblock)+'&toBlock='+str(endblock)+'&address='+address+'&topic0='+topic0+'&topic0_1_opr=and&topic1='+topic1+'&apikey='+APIKey
# lgs  = requests.get(Logs)
# lgs  = pd.read_json(lgs.text)
#
# # Collect data
# trades = []
# cols = ['Block','Time', 'SellUSDC', 'SellWETH', 'BuyUSDC', 'BuyWETH']
#
# for i in np.arange(lgs.shape[0]):
#
#     tx_hash = lgs.iloc[i,2]['transactionHash']
#
#     try:
#
#         receipt = w3.eth.getTransactionReceipt(tx_hash)
#
#         # We need to filter out the log of the exact event we want to decode
#         # pool.events.Swap().processReceipt(event) can only handel one log
#         relevantlogs = [i for index, i in enumerate(receipt['logs'])
#                     if receipt['logs'][index]['address'].upper() == '0x853ee4b2a13f8a742d64c8f088be7ba2131f670d'.upper()
#                     if receipt['logs'][index]['topics'][0] == HexBytes('0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822')]
#
#         event = {}
#         event['logs'] = relevantlogs
#
#     except:
#         print('Error for transaction: '+ tx_hash)
#
#     # Decode the event to get information
#     logs = pool.events.Swap().processReceipt(event)
#
#     # Collect information in a pd dataframe
#     Data = pd.DataFrame([[None]*len(cols)], columns = cols)
#     SellUSDC = np.round(logs[0]['args']['amount0In'] / 1e6,5)
#     SellWETH = np.round(logs[0]['args']['amount1In'] / 1e18,6)
#
#     BuyUSDC = np.round(logs[0]['args']['amount0Out'] / 1e6,5)
#     BuyWETH = np.round(logs[0]['args']['amount1Out'] / 1e18,6)
#
#     Data.iloc[0,0] = logs[0]['blockNumber']
#     Data.iloc[0,1] = datetime.fromtimestamp(int(lgs.iloc[i,2]['timeStamp'],16))
#     Data.iloc[0,2] = SellUSDC
#     Data.iloc[0,3] = SellWETH
#     Data.iloc[0,4] = BuyUSDC
#     Data.iloc[0,5] = BuyWETH
#
#     # Collect dataframea
#     trades.append(Data)
