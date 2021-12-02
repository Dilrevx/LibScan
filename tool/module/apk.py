# 文件描述信息


import csv
import os
import datetime
import config
import hashlib

from config import LOGGER
from util import valid_method_name
from constant import Constant

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes import dvm

JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11}
JAVA_BASIC_TYPR_ARR_DICT = {"[B": 13, "[S": 14, "[I": 15, "[J": 16, "[F": 17, "[D": 18, "[Z": 19, "[C": 20}
RETURN_JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11, "V": 12}

class Apk(object):

    def __init__(self, apk_path):
        # 库的基本信息
        self.apk_name = None # 库文件名

        # 后续用于匹配的库信息
        self.classes_dict = dict() # 记录apk中的所有类信息
        self.nodes_dict = dict()  # 记录方法内的每一个节点信息

        # 初始化ThirdLib对象时，解析lib对应的dex1文件
        LOGGER.info("开始解析 %s ...", os.path.basename(apk_path))
        self._parse_apk(apk_path)
        LOGGER.info("%s 解析完成", os.path.basename(apk_path))

    # 读取obf_tpl_pkg.csv文件，根据库的显示名称确定库的真实包名
    def _parse_apk(self, apk_path):
        # 使用AndroGuard反编译apk
        time_start = datetime.datetime.now()
        try:
            apk_obj = APK(apk_path)
        except Exception:
            return 0, 0
        time_end = datetime.datetime.now()
        decompile_time = time_end - time_start
        LOGGER.info("反编译完成，用时：%d", decompile_time.seconds)

        # 提取apk信息
        time_start = datetime.datetime.now()
        for dex in apk_obj.get_all_dex():

            dex_obj = DalvikVMFormat(dex)
            analysis_obj = Analysis(dex_obj)

            for cls in dex_obj.get_classes():
                class_name = cls.get_name().replace("/", ".")[1:-1]
                class_name_short = class_name[class_name.rfind(".") + 1:]
                if class_name_short.startswith("R$"):  # 不考虑资源类
                    continue

                class_info_list = []
                method_num = 0  # 记录类中参与匹配的方法数量
                class_opcode_num = 0  # 记录每个类中参与匹配的opcode个数
                class_bloom_filter = {}  # 类过滤器，记录当前类在布隆过滤器中的各项位置信息
                class_method_md5_list = []
                class_method_info_dict = {}

                # 获取并记录类在布隆过滤器中的如下信息：是接口、是抽象类、是枚举类、是静态类、是final类、存在非Object父类
                super_class_name = cls.get_superclassname()
                class_access_flags = cls.get_access_flags_string()

                # print(class_access_flags)
                if class_access_flags == Constant.ZERO or class_access_flags == Constant.PUBLIC:
                    class_bloom_filter[1] = Constant.YES
                elif class_access_flags.find("interface") != -1:
                    class_bloom_filter[2] = Constant.YES
                elif class_access_flags.find("interface") == -1 and class_access_flags.find("abstract" != -1):
                    class_bloom_filter[3] = Constant.YES
                elif class_access_flags.find("enum") != -1:
                    class_bloom_filter[4] = Constant.YES
                elif class_access_flags.find("static") != -1:
                    class_bloom_filter[5] = Constant.YES
                if super_class_name != Constant.OBJECT:
                    class_bloom_filter[6] = Constant.YES

                # 获取并记录字段在布隆过滤器中的如下信息：有final、无final、有static、无static、java引用类型字段、Android引用类型字段、java基本类型字段（8种）、其他引用类型字段
                # if len(cls.get_fields()) == 0: print("类无字段！")
                if len(cls.get_fields()) == 0:  # 无字段
                    class_bloom_filter[7] = Constant.YES
                else:
                    for EncodedField_obj in cls.get_fields():
                        a = 1

                        field_access_flag = EncodedField_obj.get_access_flags_string()
                        field_des = EncodedField_obj.get_descriptor()

                        if field_access_flag.find("static") == -1:
                            a = 2

                        if field_des.startswith("Ljava/lang/Object;"):
                            b = 1
                        elif field_des.startswith("Ljava/lang/String"):
                            b = 2
                        elif field_des.startswith("Ljava/"):
                            b = 3
                        elif field_des in JAVA_BASIC_TYPR_DICT:
                            b = JAVA_BASIC_TYPR_DICT[field_des]
                        # 字段属于数组类型
                        elif field_des.startswith("[Ljava/"):
                            b = 12
                        elif field_des in JAVA_BASIC_TYPR_ARR_DICT:
                            b = JAVA_BASIC_TYPR_ARR_DICT[field_des]
                        elif field_des.startswith("["):
                            b = 21
                        else:
                            b = 22

                        # 将字段信息加入类过滤器中
                        self._add_class_filter(class_bloom_filter, 7 + (a - 1) * 22 + b)

                for method in cls.get_methods():

                    if method.full_name.find("<init>") != -1 or method.full_name.find("<clinit>") != -1:
                        continue

                    method_descriptor = ""

                    k = 1
                    method_access_flags = method.get_access_flags_string()
                    if method_access_flags.find("static") == -1:
                        k = 2

                    # 每个方法设置两个整型值m,n，用来计算当前方法参数与返回值特征组合在布隆过滤器中的下标
                    method_info = method.get_descriptor()
                    # 记录方法返回值类型
                    method_return_value = method_info[method_info.rfind(")") + 1:]

                    if method_return_value.startswith("Ljava/lang/Object;"):
                        m = 1
                    elif method_return_value.startswith("Ljava/lang/String"):
                        m = 2
                    elif method_return_value.startswith("Ljava"):
                        m = 3
                    elif method_return_value in RETURN_JAVA_BASIC_TYPR_DICT:
                        m = RETURN_JAVA_BASIC_TYPR_DICT[method_return_value]
                    # 返回值为数组类型
                    elif method_return_value.startswith("[Ljava/"):
                        m = 13
                    elif method_return_value in JAVA_BASIC_TYPR_ARR_DICT:
                        m = JAVA_BASIC_TYPR_ARR_DICT[method_return_value] + 1
                    elif method_return_value.startswith("["):
                        m = 22
                    else:
                        m = 23

                    # 记录方法参数类型
                    method_param_info = method_info[method_info.find("(") + 1:method_info.find(")")]
                    parm_info = {}
                    # 统计方法每个参数信息
                    if method_param_info == "":  # 方法无参数
                        n = 1
                    else:
                        for parm in method_param_info.split(" "):
                            if parm.startswith("Ljava/"):
                                parm_info[1] = 1
                            elif parm in Constant.JAVA_BASIC_TYPE:
                                parm_info[2] = 1
                            elif parm.startswith("["):
                                parm_info[3] = 1
                            else:
                                parm_info[4] = 1

                        if len(parm_info) == 1:
                            if 1 in parm_info:
                                n = 2
                            elif 2 in parm_info:
                                n = 3
                            elif 3 in parm_info:
                                n = 4
                            elif 4 in parm_info:
                                n = 5
                        elif len(parm_info) == 2:
                            if 1 in parm_info and 2 in parm_info:
                                n = 6
                            elif 1 in parm_info and 3 in parm_info:
                                n = 7
                            elif 1 in parm_info and 4 in parm_info:
                                n = 8
                            elif 2 in parm_info and 3 in parm_info:
                                n = 9
                            elif 2 in parm_info and 4 in parm_info:
                                n = 10
                            elif 3 in parm_info and 4 in parm_info:
                                n = 11
                        elif len(parm_info) == 3:
                            if 4 not in parm_info:
                                n = 12
                            elif 3 not in parm_info:
                                n = 13
                            elif 2 not in parm_info:
                                n = 14
                            elif 1 not in parm_info:
                                n = 15
                        else:
                            n = 16

                    # 将类中方法信息加入类过滤器中
                    self._add_class_filter(class_bloom_filter, 51 + (k - 1) * 368 + (m - 1) * 16 + n)

                    method_name = valid_method_name(method.full_name)

                    method_info_list = []

                    if method.full_name.startswith("Ljava"):
                        continue

                    bytecode_buff = dvm.get_bytecodes_method(dex, analysis_obj, method)

                    # if method.get_access_flags_string().find("native") == -1:
                    method_opcodes = self._get_method_info(bytecode_buff, method_name)
                    # method_nodes_count[valid_method_name(method.full_name)]=node_count

                    if method_opcodes == "" or len(method_opcodes.split(" ")) < config.min_method_opcode_num \
                            or len(method_opcodes.split(" ")) > config.max_opcode_len:
                        continue

                    method_num += 1
                    method_opcode_num = len(method_opcodes.split(" "))
                    class_opcode_num += method_opcode_num

                    methodmd5 = hashlib.md5()
                    methodmd5.update(method_opcodes.encode("utf-8"))
                    method_md5_value = methodmd5.hexdigest()

                    class_method_md5_list.append(method_md5_value)

                    method_info_list.append(method_md5_value)
                    method_info_list.append(method_opcodes)
                    method_info_list.append(method_opcode_num)
                    method_info_list.append(method_descriptor[:-1])

                    # 避免类中方法重载的影响，所以对于重载的方法，必须保证方法名称不同
                    class_method_info_dict[method_name] = method_info_list

                # 在分析完类中所有方法后，考虑当前类是接口或者抽象类的情况（关键：抽象类或者接口中也可以有非抽象方法）
                if len(class_method_md5_list) == 0 and (class_access_flags.find(Constant.INTERFACE) != -1 or
                                                        class_access_flags.find(Constant.ABSTRACT) != -1):
                    # 只考虑有抽象方法的接口或抽象类
                    if len(cls.get_methods()) == 0:
                        continue
                    # 添加apk接口或抽象类中的方法数量，注意此时类值列表长度为1，而不是5
                    class_info_list = [len(cls.get_methods()), class_bloom_filter]
                    self.classes_dict[cls.get_name().replace("/", ".")[1:-1]] = class_info_list
                    continue

                # 说明类中只有init构造方法，不考虑
                if len(class_method_info_dict) == 0:
                    continue

                if len(class_method_md5_list) == 0:
                    continue

                class_method_md5_list.sort()
                class_md5 = ""
                for method_md5 in class_method_md5_list:
                    class_md5 += method_md5

                classmd5 = hashlib.md5()
                classmd5.update(class_md5.encode("utf-8"))
                class_md5_value = classmd5.hexdigest()

                # 添加每个类的所有信息
                class_info_list.append(class_md5_value)
                class_info_list.append(method_num)
                class_info_list.append(class_opcode_num)
                class_info_list.append(class_bloom_filter)
                class_info_list.append(class_method_info_dict)

                self.classes_dict[cls.get_name().replace("/", ".")[1:-1]] = class_info_list

        time_end = datetime.datetime.now()
        extract_info_time = time_end - time_start
        LOGGER.info("解析apk完成，用时：%d", extract_info_time.seconds)

    # 获取每个方法的opcode序列字符串
    def _get_method_info(self, bytecode_buff, inter_method_name):
        method_opcode_seq = ""  # 记录当前方法的opcode序列
        num = 1  # 标记方法的第几个节点
        node_opcode_seq = ""  # 记录当前节点的opcode序列

        line_s = bytecode_buff.split("\n")
        for line in line_s:
            if line != "" and line.startswith("\t") and (not line.startswith("	(")) and len(line.strip()) > 20:
                # 获取当前行的opcode
                line = line.strip()
                templine = line[line.find(")") + 2:]
                if templine.find(" ") != -1:
                    dvmopcode = templine[:templine.find(" ")]
                else:
                    dvmopcode = templine

                if dvmopcode.find(":") == -1 and dvmopcode != "":
                    if dvmopcode.endswith("-payload"):  # fill-array-data-payload
                        dvmopcode = dvmopcode[:dvmopcode.rfind("-")]

                    if dvmopcode.find("/") != -1:
                        dvmopcode = dvmopcode[:dvmopcode.find("/")]
                    if not dvmopcode.startswith("move") and dvmopcode != "nop":  # 混淆过程，会移除掉库方法中的某些move指令
                        method_opcode_seq = method_opcode_seq + dvmopcode + " "
                        node_opcode_seq = node_opcode_seq + dvmopcode + " "

                if line.find("invoke") != -1:
                    invoke_info = line[line.find("L"):]
                    method_info = invoke_info.replace("->", " ").replace("(", " (")

                    if method_info.startswith("Ljava"):
                        continue

                    node_info = [node_opcode_seq[:-1]]
                    invoke_method_valid_name = valid_method_name(method_info)
                    node_info.append(invoke_method_valid_name)
                    self.nodes_dict[inter_method_name + "_" + str(num)] = node_info
                    num += 1
                    node_opcode_seq = ""

        # if node_opcode_seq != "": 可能存在一些opcode为空的方法，也要记录
        node_info = [node_opcode_seq[:-1], ""]
        self.nodes_dict[inter_method_name + "_" + str(num)] = node_info

        return method_opcode_seq[:-1]

    # 将指定元素加入类过滤器中
    def _add_class_filter(self, class_filter, index):
        index_num = class_filter.get(index, 0)
        count = index_num + 1
        if count > count.filter_record_limit:
            count = count.filter_record_limit
        class_filter[index] = count




