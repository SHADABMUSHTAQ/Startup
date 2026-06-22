import os
import re

emoji_pattern = re.compile(r'[✅⚠️❌🚀🛑🔄🔁🛡️🛠️💳🚨🔥🔐🔴🔌ℹ️]')

for root, dirs, files in os.walk(r'C:\Users\Lenovo\Desktop\Startup-backend\app'):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = emoji_pattern.sub('', content)
            
            if new_content != content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Cleaned {filepath}')
