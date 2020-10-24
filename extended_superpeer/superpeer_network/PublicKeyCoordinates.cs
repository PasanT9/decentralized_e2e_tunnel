using Newtonsoft.Json;

namespace superpeer_network
{
    public class PublicKeyCoordinates
    {
        public byte[] X;
        public byte[] Y;

        public PublicKeyCoordinates(byte[] x, byte[] y)
        {
            Initialize(x, y);
        }

        private void Initialize(byte[] x, byte[] y)
        {
            X = x;
            Y = y;
        }

        override public string ToString()
        {
            string jsonString = JsonConvert.SerializeObject(this);
            return jsonString;
        }
    }
}