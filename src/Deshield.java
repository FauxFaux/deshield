import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;


public class Deshield {

	private static final int HEADER_LENGTH = 312;
	private static final int LOCATION_OF_SIX = 260;
	private static final int LOCATION_OF_SIZE = 268;
	private static final int LENGTH_OF_LONG = 8;

	private static final int BLOCK_SIZE = 1024;

	private static final Charset CHARSET = Charset.forName("UTF-8");

	/** Magic used in filename key generation. */
	private static final byte[] MAGIC = { 0x13, 0x35, (byte) 0x86, 0x07 };

	public static void main(String[] args) throws IOException {
		final FileInputStream fis = new FileInputStream(args[0]);

		// the header:
		readAndCheck(fis, "InstallShield\0\007");
		// this is entirely null:
		fis.skip(31);

		try {
			while (7 != fis.available()) {
				final byte[] header = read(fis, HEADER_LENGTH);
				// I don't know what this is.  The rest of the header is null.
				if (6 != header[LOCATION_OF_SIX])
					throw new AssertionError();

				// Filename is the start of the header:
				final byte[] filename = upToNull(header);
				final String name = new String(filename, CHARSET);
				final long dataLength = readLong(Arrays.copyOfRange(header, LOCATION_OF_SIZE, LOCATION_OF_SIZE + LENGTH_OF_LONG));
				System.out.print("Extracting " + name + " (" + dataLength + " bytes)..");

				final byte[] key = generateKey(filename);

				if (dataLength > Integer.MAX_VALUE)
					throw new AssertionError();


				final byte buf[] = new byte[(int)dataLength];
				fis.read(buf);

				for (int i = 0; i < buf.length; i++) {
					buf[i] = cockyBitTwiddling(buf[i], key[(i % BLOCK_SIZE) % filename.length]);
				}

				final FileOutputStream fos = new FileOutputStream(name);
				try {
					fos.write(buf);
				} finally {
					fos.close();
				}
				System.out.println(". done.");
			}
		} catch (EndOfFileException e) {
			// reached end of file archive
		}
		System.out.println("Done.");
	}

    private static byte[] upToNull(byte[] header) {
		for (int i = 0; i < header.length; i++) {
			if (0 == header[i])
				return Arrays.copyOfRange(header, 0, i);
		}
		throw new AssertionError("No null byte in header");
	}


    /** Generate the file key; a function of the filename.
     * bytewise xor of filename with cycled MAGIC. */
    private static byte[] generateKey(byte[] filename) {
    	byte[] ret = new byte[filename.length];

    	for (int i = 0; i < filename.length; i++)
    		ret[i] = (byte) (filename[i] ^ MAGIC[i % MAGIC.length]);

    	return ret;
    }

    /** swap the nibbles in the data, xor it with the key, then binary not. */
    private static byte cockyBitTwiddling(byte data, byte key) {
    	return (byte) ((~(swapNibble(data) ^ key)) & 0xff);
    }

    /** For the byte 0xQR, return 0xRQ. */
	private static int swapNibble(byte data) {
		return ((data << 4) & 0xf0) | ((data >> 4)) & 0x0f;
	}

	/** Read an LE long. */
	private static long readLong(byte[] readbytes) {
        return (((long)readbytes[7] << 56) +
                ((long)(readbytes[6] & 255) << 48) +
		((long)(readbytes[5] & 255) << 40) +
                ((long)(readbytes[4] & 255) << 32) +
                ((long)(readbytes[3] & 255) << 24) +
                ((readbytes[2] & 255) << 16) +
                ((readbytes[1] & 255) <<  8) +
                ((readbytes[0] & 255) <<  0));
    }

	static class EndOfFileException extends IOException {
		// nothind at all
	}

	private static byte[] read(InputStream fis, int i) throws IOException {
		byte[] b = new byte[i];
		final int readed = fis.read(b);
		if (0 == readed)
			throw new EndOfFileException();
		if (readed != i)
			throw new IOException("Unable to read requested amount");
		return b;
	}

	private static void readAndCheck(InputStream fis, String string) throws IOException {
		final byte[] stringBytes = string.getBytes(CHARSET);
		final byte[] readBytes = new byte[stringBytes.length];
		fis.read(readBytes);
		if (!Arrays.equals(stringBytes, readBytes))
			throw new AssertionError("Header: " + new String(readBytes, CHARSET));
	}
}
