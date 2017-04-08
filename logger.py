# --*--coding: utf-8 --*--

def logger(title, message=''):
    '''
    @param {String | Number} params.title
    @param {String | Number} params.message
    '''
    w = '\033[0m'
    g = '\033[32m'
    print(''.join([g, title, w, message]))
