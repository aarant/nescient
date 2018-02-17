
if __name__ == '__main__':
    import os
    import base64

    for path in ['banner.gif', 'nessie.gif', 'nessie_lock.gif']:
        with open(path, 'rb') as f_in:
            data = f_in.read()
            s = str(base64.b64encode(data), 'utf-8')
            root, _ = os.path.splitext(path)
            with open(root + '.py', 'w') as f_out:
                d = {'banner': 'BANNER_DATA', 'nessie': 'LOGO_DATA', 'nessie_lock': 'LOCK_DATA'}
                f_out.write(d[root] + " = '''")
                for i in range(0, len(s), 120):
                    f_out.write(s[i:i + 120])
                    f_out.write('\n')
                f_out.write("'''")
