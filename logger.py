# --*--coding: utf-8 --*--

def logger(title, message=''):
    w = '\033[0m'
    g = '\033[32m'
    print(''.join([g, title, w, message]));
