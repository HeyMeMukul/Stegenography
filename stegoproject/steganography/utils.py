from PIL import Image
import numpy as np

def decode_text_from_image(image_path):
    """
    Decodes hidden text from an image using the least significant bit (LSB) method.
    Assumes text is hidden in the image's pixel data.
    """
    image = Image.open(image_path)
    image = image.convert('RGB')  # Ensure the image is in RGB format
    pixels = np.array(image)  # Convert the image to a numpy array of pixel values

    binary_text = ''
    
    # Traverse the image pixel data and extract the least significant bit of each channel
    for row in pixels:
        for pixel in row:
            for color in pixel[:3]:  # Only RGB channels (ignore alpha if present)
                binary_text += str(color & 1)  # Extract the LSB (least significant bit)

    # Group the binary string into 8-bit chunks and convert them to characters
    decoded_text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    
    return decoded_text
