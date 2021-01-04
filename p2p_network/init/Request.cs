namespace TCP
{
    public class Request
    {
        public int status_code;
        public string body;

        public Request(int status_code, string body)
        {
            Initialize(status_code, body);
        }

        private void Initialize(int a, string b)
        {
            status_code = a;
            body = b;
        }
    }
}