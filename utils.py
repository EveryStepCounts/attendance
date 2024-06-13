import random
import string
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import qrcode
from io import BytesIO
import base64
import os

def generate_captcha():
    # Generate a random 4-character captcha text
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
    # Create an image for the captcha
    width, height = 100, 40
    img = Image.new('RGB', (width, height), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    
    # Get the absolute path to the font file
    font_path = os.path.join(os.path.dirname(__file__), 'static', 'arial.ttf')
    font = ImageFont.truetype(font_path, 24)
    
    # Draw the captcha text on the image
    for i in range(4):
        d.text((10 + i*20, 5), captcha_text[i], font=font, fill=(0, 0, 0))
    
    # Add some random lines for distortion
    for _ in range(5):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        d.line(((x1, y1), (x2, y2)), fill=(0, 0, 0), width=1)
    
    # Apply some filters to the image
    img = img.filter(ImageFilter.GaussianBlur(1))
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    captcha_image = base64.b64encode(buffer.getvalue()).decode()
    
    return captcha_text, captcha_image

def verify_captcha(input_captcha, session_captcha):
    return input_captcha.upper() == session_captcha.upper()

def generate_qrcode(distance, user_id):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(f'{user_id}-{distance}')
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode()
