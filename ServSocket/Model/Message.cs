using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServSocket.Model
{
    class Message
    {
        public byte[] text { get; set; }
        public byte[] hash { get; set; }
        public byte[] chave { get; set; }
        public byte[] sign { get; set; }
    }
}
