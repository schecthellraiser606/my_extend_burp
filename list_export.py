import sys

# Pyhton用のPayload_List作成関数
def list_export(filepath):
    new_scripts = list()
    with open(filepath, 'r', encoding='utf-8') as f:
        for script in f.read().splitlines():
            if '\"' in script and "\'" not in script:
                parse = f'\'{script}\','
                new_scripts.append(parse)
            elif "\'" in script and '\"' not in script:
                parse = f'\"{script}\",'
                new_scripts.append(parse)
    return new_scripts
  

if __name__ == '__main__':
    if sys.argv[1]:
        new_lists = list_export(sys.argv[1])
        if new_lists:
            with open('output.txt', 'w', encoding='utf-8', newline='\n') as f:
                for new_list in new_lists:
                    f.write(new_list)
                    f.write('\n')  
        else :
            print('No list')          
    else:
        print('require file name')