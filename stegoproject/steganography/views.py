from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from PIL import Image
import random
import string
import os
import io
from io import BytesIO


from django.shortcuts import render
import os
import random
import string
from django.conf import settings
from .utils import decode_text_from_image  # Assuming you have this function in utils.py

from django.conf import settings
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Helper function to generate the encryption key
def generate_key():
    # Generates a random 16-byte key consisting only of ASCII letters and digits
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16)).encode('utf-8')
# Encrypt the text using AES
def encrypt_text(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector
    padded_text = pad(text.encode('utf-8'), AES.block_size)  # Padding the text to block size
    encrypted_text = cipher.encrypt(padded_text)
    # Base64 encode the combined IV and encrypted text
    return base64.b64encode(iv + encrypted_text).decode('utf-8')

# Decrypt the text using AES
def decrypt_text(encrypted_text, key):
    try:
        # Decode the base64 encoded encrypted text
        decoded_data = base64.b64decode(encrypted_text)
    except Exception as e:
        raise ValueError("Error in base64 decoding: " + str(e))

    # Extract the initialization vector (IV) and the encrypted message
    iv = decoded_data[:AES.block_size]
    encrypted_message = decoded_data[AES.block_size:]

    # Decrypt the message using AES
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode('utf-8', errors='ignore')
    return decrypted_message


def encode_text_to_image(image_file, text, key):
    # Encrypt the text and convert to base64
    encrypted_text = encrypt_text(text, key)
    
    # Open the image and convert to RGBA mode
    image = Image.open(image_file).convert('RGBA')
    data = list(image.getdata())

    # Convert the base64 string into binary for embedding
    binary_text = ''.join(format(ord(char), '08b') for char in encrypted_text)
    binary_text += '1111111111111110'  # Delimiter

    new_data = []
    binary_index = 0
    for pixel in data:
        if binary_index < len(binary_text):
            r, g, b, a = pixel
            new_pixel = (
                (r & ~1) | int(binary_text[binary_index]),
                g, b, a
            )
            binary_index += 1
        else:
            new_pixel = pixel
        new_data.append(new_pixel)

    image.putdata(new_data)
    return image
def decode_text_from_image(image_path):
    # Open the image and convert to RGBA format
    image = Image.open(image_path).convert('RGBA')
    data = list(image.getdata())

    # Extract binary data from the image's least significant bits
    binary_text = ''
    for pixel in data:
        r, g, b, a = pixel
        binary_text += str(r & 1)  # Extract the LSB of the red channel

    # Split the binary data at the delimiter '1111111111111110' which marks the end of data
    binary_text = binary_text.split('1111111111111110')[0]

    # Convert the binary text back to encrypted text
    encrypted_text = ''
    for i in range(0, len(binary_text), 8):
        byte = binary_text[i:i + 8]
        encrypted_text += chr(int(byte, 2))

    return encrypted_text


# View for rendering the home page
def home(request):
    return render(request, 'steganography/home.html')

import base64

from io import BytesIO
from django.http import JsonResponse, HttpResponse

def hide_data(request):
    if request.method == "POST":
        image_file = request.FILES['image']
        text = request.POST['text']

        # Open the uploaded image using BytesIO to simulate a file object
        image = Image.open(BytesIO(image_file.read())).convert('RGB')
        pixels = image.load()

        # Convert text to binary
        binary_data = ''.join(format(ord(char), '08b') for char in text) + '11111111'

        # Embed the binary data into the image
        data_index = 0
        for y in range(image.height):
            for x in range(image.width):
                if data_index < len(binary_data):
                    r, g, b = pixels[x, y]

                    # Modify the LSB of the red channel
                    r = (r & ~1) | int(binary_data[data_index])
                    data_index += 1

                    # Write updated values back to the image
                    pixels[x, y] = (r, g, b)

        # Generate a random encryption key
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        # Save the modified image to a buffer
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)

        # Encode the image in Base64
        try:
            encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
            # Debugging: Print out the encoded image (first 100 characters for inspection)
            print(f"Encoded Image: {encoded_image[:100]}...")  # First 100 chars
        except Exception as e:
            return JsonResponse({'success': False, 'error': f"Error during Base64 encoding: {str(e)}"})

        # Save the key and the encoded image to the session
        request.session['encryption_key'] = key
        request.session['stego_image'] = encoded_image

        # Return success with the encryption key
        context = {
            'success': True,
            'key': key,
        }

        return render(request, 'steganography/hide.html', context)

    return render(request, 'steganography/hide.html')

def download_stego(request):
    stego_image = request.session.get('stego_image', None)
    if stego_image:
        try:
            # Debugging: Print the first 100 characters of the stored Base64 string
            print(f"Base64 Stored Image (first 100 chars): {stego_image[:100]}...")

            # Decode the Base64 string back to bytes
            stego_image_data = base64.b64decode(stego_image)
            
            # Debugging: Check the decoded bytes length
            print(f"Decoded Image Data Length: {len(stego_image_data)}")

            # Return the decoded image
            response = HttpResponse(stego_image_data, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="stego_image.png"'
            return response

        except Exception as e:
            # Log error details
            print(f"Error during decoding: {str(e)}")
            return JsonResponse({'success': False, 'error': f"Error during Base64 decoding: {str(e)}"})

    return HttpResponse("No stego image available.")


def decrypt_data(request):
    if request.method == 'POST':
        uploaded_image = request.FILES['image']

        # Save the uploaded image temporarily for decoding
        temp_image_path = os.path.join(settings.MEDIA_ROOT, 'images', uploaded_image.name)
        os.makedirs(os.path.dirname(temp_image_path), exist_ok=True)
        with open(temp_image_path, 'wb') as temp_file:
            for chunk in uploaded_image.chunks():
                temp_file.write(chunk)

        try:
            # Decode the hidden text from the image
            hidden_text = decode_text_from_image(temp_image_path)
            os.remove(temp_image_path)  # Clean up the temporary file

            # Clean out padding or delimiter bytes (for example, '\xff')
            clean_text = hidden_text.split('\xff')[0]  # Splitting at padding
            
            # Generate a mock key (in practice, this can be handled securely)
            key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

            # Pass the result to the template for rendering
            context = {
                'success': True,
                'hidden_text': clean_text,
                'key': key
            }
            return render(request, 'steganography/decrypt.html', context)

        except Exception as e:
            # If an error occurs, return it as part of the context
            context = {
                'success': False,
                'error': str(e)
            }
            return render(request, 'steganography/decrypt.html', context)

    return render(request, 'steganography/decrypt.html')

