

from Cryptodome.Cipher import AES
import binascii

hdr_byte = 0x00 # THIS BYTE MUST MATCH THE FIRST BYTE OF THE nRF INPUT PACKET (& with 0xE3 of course)
hdr = binascii.a2b_hex('%02X' % (hdr_byte & 0xE3))
plaintext = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'.encode()
key = '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'.encode()
nonce = '\x00\x00\x00\x00\x00\x02\x02\x02\x02\x02\x02\x02\x02'.encode()


print("key:   ", repr(binascii.b2a_hex(key)))
print("nonce: ", repr(binascii.b2a_hex(nonce)))
print("plain: ", repr(binascii.b2a_hex(plaintext)))

cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(hdr))
cipher.update(hdr)
ciphertext = cipher.encrypt(plaintext)
mac = cipher.digest()
print("cipher:", repr(binascii.b2a_hex(ciphertext)))
print("")
print("mac:   ", repr(binascii.b2a_hex(mac)), "(computed in python)")
#print "mac:    '6dda11ad' (computed by nRF HW)"
print("")

msg = nonce, hdr, ciphertext, mac

# We assume that the tuple ``msg`` is transmitted to the receiver:

nonce, hdr, ciphertext, mac = msg
key = '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'.encode()
cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(hdr))
cipher.update(hdr)
plaintext = cipher.decrypt(ciphertext)
print("plain: ", repr(binascii.b2a_hex(plaintext)))
try:
    cipher.verify(mac)
    print("The message is authentic: hdr=%s, pt=%s" % (repr(binascii.b2a_hex(hdr)), repr(binascii.b2a_hex(plaintext))))
except ValueError:
    print("Key incorrect or message corrupted")
