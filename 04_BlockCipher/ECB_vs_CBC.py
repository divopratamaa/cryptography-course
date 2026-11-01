"""
Week 4 - Block Ciphers: Why AES Alone Is Not Enough
====================================================
Experiments proving the ECB mode leak in AES-128:
  [1] Text data : an encrypted status column in a database (ECB vs CBC).
  [2] Image     : a padlock image is encrypted, and its pattern stays visible in ECB.

Requirements: pip install pycryptodome pillow
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from PIL import Image, ImageDraw, ImageFont

BLOCK_SIZE = 16  # AES always works on 16-byte (128-bit) blocks


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    # ECB: every block is encrypted on its own with the same key.
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, BLOCK_SIZE))


def encrypt_cbc(key: bytes, data: bytes) -> bytes:
    # CBC: a fresh random IV each time, and every block is XORed with the previous one.
    iv = get_random_bytes(BLOCK_SIZE)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, BLOCK_SIZE))


def count_unique_blocks(data: bytes) -> int:
    # Number of distinct 16-byte blocks in the data.
    return len({data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)})


# ==========================================================
# [1] LEAK IN TEXT DATA: a status column in a database
# ==========================================================
DATABASE = [
    ("001", "APPROVED"),
    ("002", "APPROVED"),
    ("003", "REJECTED"),
    ("004", "APPROVED"),
    ("005", "REJECTED"),
]


def database_demo(key: bytes) -> None:
    print("=== [1] Encrypted status column in a database (first 8 bytes) ===")
    print(f"{'ID':<4} | {'Status':<9} | {'ECB':<16} | CBC")
    print("-" * 52)

    ecb_results, cbc_results = [], []
    for record_id, status in DATABASE:
        ecb = encrypt_ecb(key, status.encode())
        cbc = encrypt_cbc(key, status.encode())[BLOCK_SIZE:]  # without the IV
        ecb_results.append(ecb)
        cbc_results.append(cbc)
        print(f"{record_id:<4} | {status:<9} | {ecb[:8].hex()} | {cbc[:8].hex()}")

    print(f"\nDistinct ciphertexts -> ECB: {len(set(ecb_results))} of {len(DATABASE)}, "
          f"CBC: {len(set(cbc_results))} of {len(DATABASE)}")


# ==========================================================
# [2] LEAK IN AN IMAGE: a padlock that stays visible
# ==========================================================
def draw_padlock(width: int = 640, height: int = 400) -> Image.Image:
    # Grayscale image: 1 byte per pixel, 640 x 400 = 256,000 bytes (a multiple of 16).
    image = Image.new("L", (width, height), 255)
    pen = ImageDraw.Draw(image)
    pen.arc((240, 50, 400, 250), start=180, end=360, fill=40, width=34)  # shackle
    pen.rectangle((240, 150, 274, 175), fill=40)                         # left leg
    pen.rectangle((366, 150, 400, 175), fill=40)                         # right leg
    pen.rounded_rectangle((200, 170, 440, 360), radius=24, fill=40)      # padlock body
    pen.ellipse((300, 220, 340, 260), fill=255)                          # keyhole
    pen.rectangle((312, 250, 328, 310), fill=255)
    return image


def encrypt_image(image: Image.Image, key: bytes, mode: str) -> Image.Image:
    data = image.tobytes()  # raw pixel values, no file header
    if mode == "ECB":
        result = AES.new(key, AES.MODE_ECB).encrypt(data)
    else:
        result = AES.new(key, AES.MODE_CBC, get_random_bytes(BLOCK_SIZE)).encrypt(data)
    return Image.frombytes("L", image.size, result)  # show the ciphertext as an image


def combine_images(images: list, labels: list) -> Image.Image:
    # Place several images side by side, each with a label above it.
    width, height = images[0].size
    gap, label_height = 20, 50
    canvas = Image.new("L", (width * len(images) + gap * (len(images) - 1), height + label_height), 255)
    pen = ImageDraw.Draw(canvas)
    try:
        font = ImageFont.load_default(size=28)
    except TypeError:  # older Pillow versions do not support the size parameter
        font = ImageFont.load_default()
    for i, (image, label) in enumerate(zip(images, labels)):
        x = i * (width + gap)
        canvas.paste(image, (x, label_height))
        pen.text((x + 4, 10), label, fill=0, font=font)
    return canvas


def image_demo(key: bytes) -> None:
    original = draw_padlock()
    ecb = encrypt_image(original, key, "ECB")
    cbc = encrypt_image(original, key, "CBC")

    original.save("padlock_original.png")
    ecb.save("padlock_ecb.png")
    cbc.save("padlock_cbc.png")
    combine_images([original, ecb, cbc],
                   ["Original image", "AES-ECB encryption", "AES-CBC encryption"]).save("padlock_comparison.png")

    total_blocks = len(original.tobytes()) // BLOCK_SIZE
    print("\n=== [2] Encrypting a 640 x 400 pixel padlock image ===")
    print(f"Total blocks                  : {total_blocks}")
    print(f"Unique blocks, original image : {count_unique_blocks(original.tobytes())}")
    print(f"Unique blocks, ECB result     : {count_unique_blocks(ecb.tobytes())}")
    print(f"Unique blocks, CBC result     : {count_unique_blocks(cbc.tobytes())}")
    print("Saved: padlock_original.png, padlock_ecb.png, padlock_cbc.png, padlock_comparison.png")


if __name__ == "__main__":
    key = get_random_bytes(BLOCK_SIZE)  # random AES-128 key, different on every run

    database_demo(key)
    image_demo(key)
