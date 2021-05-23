import pandas as pd
import datetime

def excel (h,k,v,u):
    x = datetime.datetime.now()
    fecha= ("%s-%s-%s_%sh_%sm_%ss" % (x.year, x.month, x.day, x.hour, x.minute,x.second))
    df2 = pd.DataFrame(v,
                       columns=u,
                       index=h)
    df2.to_excel("labels_agents_"+fecha+".xlsx")

def excel2 (h,k,v,u):
    x = datetime.datetime.now()
    fecha= ("%s-%s-%s_%sh_%sm_%ss" % (x.year, x.month, x.day, x.hour, x.minute,x.second))
    df2 = pd.DataFrame(k,v,
                       columns=u
                       )
    df2.to_excel("incidents_"+fecha+".xlsx")

"""
#otros ejemplos https://datatofish.com/export-dataframe-to-excel/

cars = {'Quality': [1,2,3,4],
        'Brand': ['Honda Civic','Toyota Corolla','Ford Focus','Audi A4'],
        'Price': [32000,35000,37000,45000]
        }
#df = pd.DataFrame(cars, columns = ["Quality",'Brand', 'Price'])
#df.to_excel (r'C:\cesar\python\excel.xlsx', index = False, header=True) 


data= [['a', 'b'], ['c', 'd']]
df1 = pd.DataFrame(data,
                   columns=['APP', 'ROLE'],
                   index=['HOST1', 'HOST2'])
"""