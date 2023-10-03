# #!/usr/bin/python -tt
# -*- coding: utf-8 -*-

import warnings
import socket
import sys
import time
from sys import platform
from KlAkOAPI.Params import KlAkParams, KlAkArray, paramParams
from KlAkOAPI.AdmServer import KlAkAdmServer
from KlAkOAPI.Tasks import KlAkTasks
from KlAkOAPI.HostGroup import KlAkHostGroup
from KlAkOAPI.EventProcessing import KlAkEventProcessing

def WriteInFile(s, str):
    f.open(f, s)
    f.write(str)
    f.close()

def GetServer():
    """Подключение к KSC серверу"""
    # сведения о сервере - подключитесь к серверу, установленному на текущем компьютере, используйте порт по умолчанию
    server_address = socket.getfqdn()
    server_port = 13299
    server_url = 'https://' + server_address + ':' + str(server_port)

    if platform == "win32":
        username = None  # для Windows по умолчанию используется NTLM
        password = None
    else:
        username = 'ksc_admin'  # для других платформ, использующих базовую аутентификацию, пользователь должен быть создан на сервере KSC заранее
        password = '123qweASD'

    SSLVerifyCert = 'C:\\ProgramData\\KasperskyLab\\adminkit\\1093\\cert\\klserver.cer'
    #SSLVerifyCert = '/var/opt/kaspersky/klnagent_srv/1093/cert/klserver.cer'

    # создание объекта сервера
    server = KlAkAdmServer.Create(server_url, username, password, verify=False)

    return server


def FindTask(oTasks, strDisplayName):
    strTaskIteratorId = oTasks.ResetTasksIterator(nGroupId=0, bGroupIdSignificant=True, strProductName=None,
                                                  strVersion=None, strComponentName=None, strInstanceId=None,
                                                  strTaskName=None, bIncludeSupergroups=True).OutPar("strTaskIteratorId")
    nTaskId = None
    while True:
        pTaskData = oTasks.GetNextTask(strTaskIteratorId).OutPar('pTaskData')
        if pTaskData == None or len(pTaskData) == 0:
            break
        strDN = pTaskData['TASK_INFO_PARAMS']['DisplayName']
        if strDN == strDisplayName:
            print('Задача ' + strDN)
            nTaskId = pTaskData['TASK_UNIQUE_ID']
            break

    oTasks.ReleaseTasksIterator(strTaskIteratorId)
    return nTaskId

def StatTaskByTitle(tasks, taskName):
    for task in tasks:
        if task.Name == taskName:
            # Задача найдена, выводим информацию
            print("Task ID:", task.TaskId)
            print("Task Name:", task.Name)
            print("Start Time:", task.StartTime)
            print("End Time:", task.EndTime)
            print("Status:", task.Status)
            print("Errors:", task.Errors)
            print("Result:", task.Result)
            break
    return null

def StatTaskById(tasks, taskId, filepath):
    oInfo = tasks.GetTask(taskId).RetVal()
    oStatistics = tasks.GetTaskStatistics(taskId).RetVal()
    with open(filepath, 'w') as file:
        sys.stdout = file
        print('Обработка задачи ' + oInfo['DisplayName'] + ', созданной ' + oInfo['PRTS_TASK_CREATION_DATE'].isoformat())
        print('Статистика задачи')
        print('Количество хостов, на которые модификация задачи еще не была распространена: ', oStatistics['1'])
        print('Количество хостов, на которых выполняется задача: ', oStatistics['2'])
        print('Количество хостов, на которых задача завершилась успешно: ', oStatistics['4'])
        print('Количество хостов, на которых задача завершилась с предупреждением: ', oStatistics['8'])
        print('Количество хостов, на которых задача не удалась: ', oStatistics['16'])
        print('Количество хостов, на которых было запланировано выполнение задачи: ', oStatistics['32'])
        print('Количество хостов, на которых задача была приостановлена: ', oStatistics['64'])
        print('Количество хостов, на которых запрашивается задание на перезагрузку ОС: ', oStatistics['KLTSK_NEED_RBT_CNT'])
        print('Общий процент выполнения задачи: ', oStatistics['GNRL_COMPLETED_PERCENT'])
    sys.stdout = sys.__stdout__
    return 0

def main():
    print(main.__doc__)
    warnings.filterwarnings('ignore')
    # подключитесь к серверу KSC, используя базовую аутентификацию по умолчанию
    server = GetServer()

    oHostGroup = KlAkHostGroup(server)
    nRootGroupId = oHostGroup.GroupIdGroups().RetVal()
    oTasks = KlAkTasks(server)
    mas = [['Malware Scan', 'Malware Scan', 'Malware Scan', 'Malware Scan'], ['task1stats.txt','task2stats.txt','task3stats.txt', 'task4stats.txt']]
    #вместо Malware Scan необходимо ввести названия требуемых задач из KSC-сервера, которые берутся из вкладки Устройства -> Задачи, например:
    #mas = [['Задача удаленной установки программы', 'Поиск уязвимостей и требуемых обновлений', 'Обновление баз данных и модулей', 'Обновление'], ['task1stats.txt','task2stats.txt','task3stats.txt', 'task4stats.txt']]
    for i in range(4):
        strFoundTask = FindTask(oTasks, mas[0][i])
        if strFoundTask == None or strFoundTask == '':
            print('Задача', mas[0][i], 'не была найдена')
        else:
            StatTaskById(oTasks, strFoundTask, mas[1][i])


if __name__ == '__main__':
    main()
