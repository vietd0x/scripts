from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.common.by import By

res_l = []
options = EdgeOptions()
driver = webdriver.Edge(options=options)

# Wait for the data to be rendered
driver.implicitly_wait(15)

driver.get("https://whois.inet.vn/whois?domain=dantri.com.vn")
eles = driver.find_elements(By.CLASS_NAME, "ng-binding")
for e in eles:
    res_l.append(e.text)
driver.quit()

# get data
res_l = res_l[::-1]
first_idx = res_l.index('') + 1
last_idx = res_l.index('', first_idx)-1
res_l = res_l[first_idx:last_idx][::-1]
print(res_l)

res_dict = {}
res_dict['domain_name'] = res_l[0]
res_dict['creation_date'] = res_l[1]
res_dict["expiration_date"] = res_l[2]
res_dict["org"] = res_l[3]
res_dict["status"] = res_l[4]
res_dict["registrar"] = res_l[5]
res_dict["dnssec"] = res_l[len(res_l)-1]
res_dict["name_servers"] = [val for val in res_l[6:len(res_l)-1]]
print(res_dict)
