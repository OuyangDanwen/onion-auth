public enum MessageType {
		AUTH_SESSION_START(0), AUTH_SESSION_HS1(1), 
		AUTH_SESSION_INCOMING_HS1(2), AUTH_SESSION_HS2(3), 
		AUTH_SESSION_INCOMING_HS2(4), AUTH_LAYER_ENCRYPT(5),
		AUTH_LAYER_ENCRYPT_RESP(6), AUTH_LAYER_DECRYPT(7), 
		AUTH_LAYER_DECRYPT_RESP(8), AUTH_SESSION_CLOSE(9),
		AUTH_SESSION_ERROR(10);

		private int val;

		MessageType(int val) {
			this.val = val;
		}

		public int getVal() {
			return this.val;
		}

	}