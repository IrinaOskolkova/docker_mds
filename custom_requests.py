import os
import requests
import re
import exrex

def main():
    # установить PARANOIA_LEVEL=4 в REQUEST-901-INITIALIZATION.conf (на всякий можно и в crs-setup.conf)
    # SecAction \
    #         "id:900000,\
    #          phase:1,\
    #          nolog,\
    #          pass,\
    #          t:none,\
    #          setvar:TX.PARANOIA_LEVEL=4"
    # перезапустить nginx (service nginx restart) (service nginx status)
    # включить service php7.4-fpm start
    # зачистить лог modsec_audit.log (если будет больше 12кб, записываться не будет)


    url = 'http://localhost:8080/'
    # какой лог копировать из докера
    path_modsec_audit_in_docker = 'mds:/var/log/modsec_audit.log'
    # куда копировать лог из докера
    path_modsec_audit_in_system = 'F:/DockerMDS/test/modsec_audit.log'

    # response = requests.get(url, params={}, headers={}, cookies={})

    # *****************************************************************
    # если нужно отправить файл
    # *****************************************************************

    # files = {'=': open('file.txt', 'rb')}
    # requests.post(url, files=files)


    # *****************************************************************
    # сгенерировать рандомные данные по регулрке и отправить в запросе
    # *****************************************************************

    # data = exrex.getone("^(?i:(?:[a-z]{3,10}\s+(?:\w{3,7}?://[\w\-\./]*(?::\d+)?)?/[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?|connect (?:\d{1,3}\.){3}\d{1,3}\.?(?::\d+)?|options \*)\s+[\w\./]+|get /[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?)$")
    # print(data)
    # values = {'telecom': data, 'OUT': 'sht'}
    # response = requests.post(url, headers={'Range': '12-34', 'Request-Range': '11-15'}, data=values)


    # *****************************************************************
    # просто запросы
    # *****************************************************************

    values = {'cftoken': 'session-id', 'OUT': 'sht'}
    # response = requests.get(url, headers={'proxy': '\\n'})#, data={'te': '\x25'})
    response = requests.post(url, headers={'Content-Length': '2'}, data=values)
    # response = requests.get(url + '?tr="\\\\1')
    # response = requests.get(url, params={}, headers={}, cookies={'cook': '+='})

    print(response)

    # достать лог
    os.system('docker cp ' + path_modsec_audit_in_docker + ' ' + path_modsec_audit_in_system)
    str_hash = ''
    text_mds = ''

    # выбрать последнюю часть
    try:
        with open(path_modsec_audit_in_system, 'r', encoding='utf-8') as f:
            # прочитать весь файл
            file_text = f.read()
            # найти последнюю строку с хешем
            str_hash = re.search(r'---\S+---Z--\n\n$', file_text).group(0)
            # выбрать часть с правилами
            str_hash = str_hash.replace('Z--\n\n', '')
            text_mds = re.search(str_hash + 'H--' + '[\S\s]+' + str_hash + 'I--', file_text).group(0)

            # полный лог н всякий случай
            full_log = re.search(str_hash + 'A--' + '[\S\s]+' + str_hash + 'Z--', file_text).group(0)
    except:
        print(id)

    # показать хеш последнего лога (если ни одно правило не сработает, то хеш будет от старого лога)
    print(str_hash)
    # вывести id всех сработавших правил
    print('\n'.join(re.findall(r'id "\d{6}"', text_mds)))
    print('\n\n')

    # весь лог
    print(full_log)

