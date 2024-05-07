# 执行分析的核心过程
import multiprocessing.managers
import multiprocessing.util
import os
import random
import multiprocessing
import datetime
import time
import sys
from typing import Dict, List, Set, Tuple, Union
import networkx as nx
import math

from config import LOGGER, detect_type, class_similar, lib_similar, max_thread_num
from lib import ThirdLib
from apk import Apk
from util import split_list_n_list, deal_opcode_deq

# 为接口或抽象类中没有方法体的方法赋予权重值参与得分计算
abstract_method_weight = 3  # 一般不调
# 定义允许的最大递归深度
sys.setrecursionlimit(5000)


def get_methods_jar_map() -> Dict[str, str]:
    """
    open `conf/methodes_jar.txt` and parse k:v

    Returns:
        method:jar
    """
    methodes_jar = {}
    with open("conf/methodes_jar.txt", "r", encoding="utf-8") as file:
        for line in file.readlines():
            line = line.strip("\n")
            methodes_jar[line[: line.find(":")]] = line[line.find(":") + 1 :]

    return methodes_jar


def get_lib_name(lib: str):
    """
    查询 `conf/lib_name_map.csv`，返回 package 名(替换/ -> .)

    根据库的显示名称确定库的真实包名 (jsoup-1.9.2 -> org.jsoup)

    若文件中未定义，则直接返回库名去掉 .dex。该事件记录于 [DEBUG]

    注：包名的 "." 在 jar 包内作为压缩包的路径分隔符。所以需要一个替换
    """
    lib_name_version = lib[: lib.rfind(".")]

    if detect_type == "lib":
        return lib_name_version

    import csv

    csv_reader = csv.reader(open("conf/lib_name_map.csv", encoding="utf-8"))
    csv_reader = list(csv_reader)

    lib_name_dict: Dict[str, str] = {}
    for line in csv_reader:
        lib_name_dict[line[0]] = line[1]

    if lib_name_version not in lib_name_dict:
        LOGGER.debug(
            "没有在lib_name_map.csv文件中找到库对应的真实名称信息：%s", lib_name_version
        )
        return lib_name_version

    return lib_name_dict[lib_name_version].replace("/", ".")


def get_opcode_coding(path):
    """
    打开 `conf/opcodes_encoding`，读取 opcode 及对应编号(编号从1到232)
    """
    opcode_dict: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as file:
        for line in file.readlines():
            line = line.strip("\n")
            if line != "":
                opcode = line[: line.find(":")]
                num = line[line.find(":") + 1 :]
                opcode_dict[opcode] = num

    return opcode_dict


def sub_method_map_decompile(
    lib_folder: str,
    libs: List[str],
    global_lib_info_dict: Dict[str, ThirdLib],
    shared_lock_lib_info,
):
    """
    :lib_folder: TPL dex folder
    :libs: contains a part of result from os.listdir(lib_folder) (shuffled)
    :global_lib_info_dict: global cache. 记忆化存储 .dex 的反编译结果
    :lock: 用来锁 methodes_jar.txt

    子进程 runner, 为每个 lib: lib in libs 对应的 dex 文件构建 ThirdLib 对象。并记录<方法>:<所属库文件名> 的映射到 methods_jar.txt 中
    """
    for lib in libs:
        lib_obj = ThirdLib(lib_folder + "/" + lib)

        # 记录库反编译信息对象，这个 lock 纯小丑
        shared_lock_lib_info.acquire()
        global_lib_info_dict[lib] = lib_obj
        shared_lock_lib_info.release()

        # 写入当前分析的所有库中的方法名与所属库到methods_jar.txt中，用于后续调用依赖库方法信息获取
        LOGGER.debug("写入方法所属库信息...")
        shared_lock_lib_info.acquire()
        with open("conf/methodes_jar.txt", "a+", encoding="utf-8") as file:
            for class_info_list in lib_obj.classes_dict.values():
                """
                TODO: what is class_info_list?
                """
                if len(class_info_list) == 5:
                    class_method_info_dict = class_info_list[4]
                    for method_name in class_method_info_dict:
                        file.write(method_name + ":" + lib + "\n")
        shared_lock_lib_info.release()


def sub_decompile_lib(
    lib_folder: str,
    libs: List[str],
    global_lib_info_dict: Dict[str, ThirdLib],
    shared_lock_lib_info,
    methodes_jar: Dict[str, str],
    global_dependence_relation: List[Tuple[str, str]],
    global_dependence_libs: List[str],
    shared_lock_dependence_info,
    loop_dependence_libs: List,
):
    """
    实现子进程提前反编译所有单个库 ?

    1. 将 libs 添加到 global_lib_info_dict 中（大部分应该重复）
    2. 对于每个 lib: lib in libs，从 ThirdLib 成员获取 lib 调用的所有 method。
    3. 通过 methodes_jar.txt 判定 method 是否在检测范围
    4. 添加 relation (lib, invoke_lib) （包名对包名）
    5. lib, invoke_lib 添加到 global_dependence_libs 中
    """
    # Logger.error("%s 开始运行...", process_name)

    for lib in libs:
        lib_name = get_lib_name(lib)
        if lib not in global_lib_info_dict:
            lib_obj = ThirdLib(lib_folder + "/" + lib)

            # 记录库反编译信息对象
            shared_lock_lib_info.acquire()
            global_lib_info_dict[lib] = lib_obj
            shared_lock_lib_info.release()
        else:
            lib_obj = global_lib_info_dict[lib]

        if len(loop_dependence_libs) > 0:  # TODO: what is loop_dependence_libs?
            continue

        # 记录库依赖信息(调用的所有方法)
        invoke_other_methodes = lib_obj.invoke_other_methodes
        for invoke_method in invoke_other_methodes:
            if (
                invoke_method not in methodes_jar
            ):  # handle the case that function call is out of what we can detect
                continue

            invoke_lib_name = get_lib_name(methodes_jar[invoke_method])

            if invoke_lib_name == lib_name:
                continue

            dependence_relation = (lib_name, invoke_lib_name)

            shared_lock_dependence_info.acquire()
            if lib_name not in global_dependence_libs:
                global_dependence_libs.append(lib_name)
            if invoke_lib_name not in global_dependence_libs:
                global_dependence_libs.append(invoke_lib_name)
            if dependence_relation not in global_dependence_relation:
                global_dependence_relation.append(dependence_relation)
            shared_lock_dependence_info.release()


# 反编译lib，得到粗粒度的类信息字典，键为类名，值为类中所有方法opcode序列的hash值排序组合字符串
# 注：将库的方法中opcode个数小于3的方法排除
def get_lib_info(
    lib: str,
    methodes_jar: Dict[str, str],
    cur_libs: Set[str],
    global_jar_dict: Dict[str, str],
    global_finished_jar_dict: Dict[str, Tuple],
    global_running_jar_list: List[str],
    shared_lock_libs,
    global_lib_info_dict: Dict[str, ThirdLib],
    loop_dependence_libs: List[str],
) -> ThirdLib:
    """
    修改 cur_libs，global_lib_info_dict
    将调用库的node_dict合并到当前 lib_obj 的node_dict中，并返回 lib_obj.node_dict

    解析依赖关系，将非循环的依赖库按照是否已分析过分别加入 dependence_libs / cur_lib。对于已分析的 lib_name, 通过本函数递归地得到 lib_obj, 并将其 node_dict 合并到当前 lib_obj 的 node_dict 中。
    """
    if lib in cur_libs:
        return []  # ? why not None
    lib_name = get_lib_name(lib)
    # 记录当前已经加入内容的依赖库
    cur_libs.add(lib_name)

    shared_lock_libs.acquire()
    lib_obj = global_lib_info_dict[lib]
    shared_lock_libs.release()
    nodes_dict = lib_obj.nodes_dict  # node 是以 invoke 分割的代码段
    invoke_other_methodes = lib_obj.invoke_other_methodes  # 其他类的 callee 方法名

    # 只有当当前库依赖的库属于循环依赖库，才不考虑该依赖库，即使当前库属于循环依赖库，也继续判断，因为可能存在其依赖的部分库不存在循环依赖，这部分库的内容应该加入进来
    dependence_libs = set()  # 当前库依赖库包名的集合（结果集合，没结果的库不加入）
    for invoke_method in invoke_other_methodes:
        if invoke_method not in methodes_jar:
            continue

        invoke_lib_name = get_lib_name(methodes_jar[invoke_method])

        # 如果调用库属于循环依赖库，则不考虑
        if invoke_lib_name in loop_dependence_libs or invoke_lib_name == lib_name:
            continue

        if invoke_lib_name not in cur_libs and invoke_lib_name not in dependence_libs:
            # 得到调用库的唯一标识名
            shared_lock_libs.acquire()
            if (
                invoke_lib_name in global_jar_dict
                or invoke_lib_name in global_running_jar_list
            ):  # 说明依赖库尚未分析或者正在分析中
                # print("存在未完成的依赖：", lib_name_key)
                # 记录下库依赖关系
                shared_lock_libs.release()
                return None
            elif (
                invoke_lib_name in global_finished_jar_dict
                and invoke_lib_name not in cur_libs
            ):  # 说明依赖库已经分析了，同时有检测结果，则需加入结果
                shared_lock_libs.release()
                dependence_libs.add(invoke_lib_name)
            else:  # 说明依赖库已经分析了，但是不存在于当前apk中，所以无需引入该依赖库
                shared_lock_libs.release()
                cur_libs.add(invoke_lib_name)

    # 到此说明当前库依赖的库都已经分析完成了，需要引入的依赖库存在于dependence_libs集合中，依次加入所有依赖库即可即可
    for lib_name_key in dependence_libs:
        result = []
        invoke_lib = global_finished_jar_dict[lib_name_key][0].split(" and ")[0]

        invoke_lib_obj = None
        if os.path.exists("../libs_dex/" + invoke_lib):
            invoke_lib_obj = get_lib_info(
                invoke_lib,
                methodes_jar,
                cur_libs,
                global_jar_dict,
                global_finished_jar_dict,
                global_running_jar_list,
                shared_lock_libs,
                global_lib_info_dict,
                loop_dependence_libs,
            )
            if len(result) != 0:
                LOGGER.debug("加入其他库内容：%s", invoke_lib)
        else:
            LOGGER.debug("当前检测库中缺少依赖库：%s", invoke_lib)

        if invoke_lib_obj == None:
            continue

        # 将调用库的node_dict合并到当前库的node_dict中
        nodes_dict.update(invoke_lib_obj.nodes_dict)

    lib_obj.nodes_dict = nodes_dict

    return lib_obj


# 对当前app类通过布隆过滤器进行过滤，返回满足过滤条件的类集合
def deal_bloom_filter(
    lib_class_name,
    lib_classes_dict: Dict[str, Tuple[str, int, int, Dict[int, int], Dict[str, list]]],
    app_filter: Dict[str, Tuple[Set[str], Set, Set, Set, Set, Set, Set, Set, Set, Set]],
) -> Set[str]:
    """
    :lib_classes_dict: 记录库中的所有类信息. str -> hash, method_num, cls_opcode_num, class_filter, cls_method_info_dict. 当 cls 是 interface 时，-> cls_method_num, class_filter.
    :app_filter: class_filter 的特征编号 -> [Set[class_names]] * 10. value 的 index 表示 count -1 个 特征的类集合

    其中 cls_filter maps int -> int，表示编号为 int 的特征在 cls 中出现的次数。

    过滤库中由 cls_name 指定的 cls 中，特征匹配的 apk.cls

    返回 Set[class_names] eg. {"org.apache.commons.collections4.Equator"}
    """
    if len(lib_classes_dict[lib_class_name]) == 2:  # 说明当前是一个接口或者抽象类
        lib_class_bloom_info = lib_classes_dict[lib_class_name][1]
    else:
        lib_class_bloom_info = lib_classes_dict[lib_class_name][3]

    satisfy_classes: Set[str] = set()
    satisfy_count = 0

    for index in lib_class_bloom_info:

        if index not in app_filter:  # 表示当前app中不存在具有此特征的类
            return set()

        # 获取app中所有满足该条件的类集合
        count = lib_class_bloom_info[index]
        if satisfy_count == 0:
            satisfy_classes = app_filter[index][count - 1]
            satisfy_count += 1
        else:
            satisfy_classes = satisfy_classes & app_filter[index][count - 1]

    return satisfy_classes


# 处理得到apk所有类中每个类的过滤结果集，记录在filter_result字典中，并统计过滤效果信息
def pre_match(apk_obj: Apk, lib_obj: ThirdLib) -> Dict[str, Set[str]]:
    """
    执行 `pre_match`: 要求 lib.cls 与 apk.cls 具有相同的 signature，找到 lib 中能 match apk 的所有 lib.cls.

    对于每个 lib_name.cls_name, 返回 APK 中与 lib_name.cls_name 可能 matched 的所有 apk.cls

    returns: Dict[lib.cls_name, Set[apk.cls_name]]
    """
    succ_filter_num = 0
    lib_filter_set_sum = 0

    lib_classes_dict = lib_obj.classes_dict
    app_filter = apk_obj.app_filter

    filter_result: Dict[str, Set[str]] = {}
    for lib_class_name in lib_classes_dict:

        satisfy_classes = deal_bloom_filter(
            lib_class_name, lib_classes_dict, app_filter
        )

        if len(satisfy_classes) > 0:
            filter_result[lib_class_name] = satisfy_classes

        lib_filter_set_sum += len(satisfy_classes)

        if len(satisfy_classes) == 0:
            succ_filter_num += 1

    # apk中被过滤的类 / apk中所有的类（越大越好）
    # filter_rate = succ_filter_num / len(lib_classes_dict)
    # apk中每个类的过滤结果集平均长度 / lib中所有的类数目（越大越好）
    # filter_effect = 1 - (lib_filter_set_sum / len(lib_classes_dict)) / len(apk_obj.classes_dict)

    # return filter_result, filter_rate, filter_effect
    return filter_result


def match(apk_method_opcode_list, lib_method_opcode_list, opcode_dict) -> bool:
    """
    通过过滤器的方式检测apk方法与lib方法是否匹配(库中方法的opcode必须存在于apk方法中）

    采用包含的方式来判断匹配，是为了抵御控制流随机化，插入无效代码、部分代码位置随机化等
    """
    # 先使用apk方法设置过滤器的每一位
    method_bloom_filter = {}
    for opcode in apk_method_opcode_list:
        method_bloom_filter[opcode_dict[opcode]] = 1

    # 再拿apk类来过滤器中进行匹配
    for opcode in lib_method_opcode_list:
        if opcode != "" and opcode_dict[opcode] not in method_bloom_filter:
            return False

    return True


# 进行apk与某个lib的粗粒度匹配，得到粗粒度相似度值、所有完成匹配的apk类列表
def coarse_match(
    apk_obj: Apk,
    lib_obj: ThirdLib,
    filter_result: Dict[str, Set[str]],
    opcode_dict: Dict[str, str],
):
    """
    :filter_result: Dict[lib.cls_name, Set[apk.cls_name]], apk 中，与固定 lib.cls_name 匹配的所有 apk.cls_name
    :opcode_dict: opcode -> int

    for lib_class:  for apk_class:
        if abstract, 只要 lib_cls 和 apk_cls 的 method_num 相等，就匹配
        else:
            for lib_method: for apk_method:
                if lib_method 与 apk_method 的 descriptor 相等，进行进一步比较。
                在 match 的前提下（lib_method 的 opcode 均出现于 apk），取 lib_method 与 apk_method 的 argmin( |lib_method_opcode_num - apk_method_opcode_num| ) 作为最佳匹配，记录 lib_method -> apk_method 于 methods_match_dict 中。

            把每个 method 匹配后，计算 sum(apk_class_method.opcode_num) / apk_class.opcode_num。**若按该 APK 公式计算的比率**超过阈值 class_similar，认为 lib_class 匹配了（多个）apk_class，记录于 match_classes, 并记录 lib_class -> {apk_class -> methods_match_dict} 于 lib_class_match_dict 中。

    返回 lib_match_classes, abstract_lib_match_classes, lib_class_match_dict
    """

    # 记录每个粗粒度匹配的类中具体方法的匹配关系，用于后面细粒度确定这些方法是否是真实的匹配。
    # apk_class_methods_match_dict = {}
    lib_class_match_dict: Dict[str, Dict[str, Dict[str, str]]] = {}
    lib_match_classes: Set[str] = set()  # 用于计算lib的粗粒度匹配得分
    abstract_lib_match_classes: Set[str] = set()
    abstract_apk_match_classes: Set[str] = set()

    # 取出粗粒度匹配需要使用的数据
    lib_classes_dict = lib_obj.classes_dict
    apk_classes_dict = apk_obj.classes_dict

    for lib_class in lib_classes_dict:

        if lib_class not in filter_result:
            continue

        class_match_dict: Dict[str, Dict[str, str]] = (
            {}
        )  # apk_class -> methods_match_dict = {lib.method -> apk.method}

        filter_set = filter_result[
            lib_class
        ]  # 注意，从布隆过滤器得到的lib类可能不存在于lib_classes_dict中

        # 记录apk中所有被匹配的抽象类或者接口（直接视为最终匹配）, 不考虑apk与lib中没有具体方法实现的接口或抽象类的匹配。将抽象类的包名.cls 记录到 abstract_*_match_classes 中
        if (
            len(lib_classes_dict[lib_class]) == 2
        ):  # 说明是lib中无方法实现的抽象类或者接口
            for apk_class in filter_set:
                if (
                    apk_class in abstract_apk_match_classes
                ):  # 为实现一对一匹配，已经完成匹配的apk类不参与匹配了
                    continue

                if (
                    len(apk_classes_dict[apk_class]) > 1
                ):  # 匹配的apk中的抽象类或者接口也一定要是无内容的
                    continue

                apk_class_method_num = apk_classes_dict[apk_class][0]
                lib_class_method_num = lib_classes_dict[lib_class][0]

                if apk_class_method_num == lib_class_method_num:
                    LOGGER.debug("接口匹配%s  ->  %s", lib_class, apk_class)
                    abstract_apk_match_classes.add(apk_class)
                    abstract_lib_match_classes.add(lib_class)
                    break

            continue

        for apk_class in filter_set:
            # 可能有些类存在于app过滤器中，但是不存在apk_classes_dict中
            if apk_class not in apk_classes_dict:
                continue

            # 保证apk中的抽象类只与lib中的抽象类匹配（因为布隆过滤器是根据<=关系过滤的，所以对于lib中的正常类，可能会被过滤出apk中的抽象类）
            if len(apk_classes_dict[apk_class]) == 1:
                continue

            # lib类中的方法数必须大于等于该apk类
            if apk_classes_dict[apk_class][1] > lib_classes_dict[lib_class][1]:
                continue

            # 进行类中方法的一对一匹配，目的是得到lib类中所有完成一对一匹配的方法（每次寻找最大相似度匹配）
            methods_match_dict: Dict[str, str] = (
                {}
            )  # 用于记录apk中类方法与对应的lib类方法匹配关系 lib.method -> apk.method
            apk_class_methods_dict = apk_classes_dict[apk_class][3]
            lib_class_methods_dict = lib_classes_dict[lib_class][4]

            """
            class_methods_dict: method_name -> [hash, opcode_seq, opcode_num, descriptor]

            opcode_seq: 'op1 op2 op3'
            descriptor: static, (ret type), param-type-list
            """

            apk_match_methods = []  # 保证apk类中的方法不会被重复匹配
            for lib_method in lib_class_methods_dict:

                # 用于记录apk方法中opcode与lib方法中去重opcode数量差值，将差值最小的视为最佳匹配
                min_method_diff_opcodes = (
                    sys.maxsize
                )  # 用于记录匹配的apk方法中去重后的opcode数量，在匹配的前提下，该数值越小，匹配度越高

                for apk_method in apk_class_methods_dict:

                    if apk_method in apk_match_methods:
                        continue

                    # 先判断方法的descriptor是否完全相同，如果不同，则无需内容匹配
                    if (
                        apk_class_methods_dict[apk_method][3]
                        != lib_class_methods_dict[lib_method][3]
                    ):
                        continue

                    # 尝试匹配方法整体MD5值
                    if (
                        apk_class_methods_dict[apk_method][0]
                        == lib_class_methods_dict[lib_method][0]
                    ):
                        if (
                            lib_method in methods_match_dict
                        ):  # 说明之前有匹配的方法已经存入methods_match_dict 与 apk_match_methods
                            apk_match_methods.remove(methods_match_dict[lib_method])
                        methods_match_dict[lib_method] = apk_method
                        apk_match_methods.append(apk_method)
                        break

                    apk_method_opcodes = apk_class_methods_dict[apk_method][1].split(
                        " "
                    )
                    lib_method_opcodes = lib_class_methods_dict[lib_method][1].split(
                        " "
                    )
                    if match(apk_method_opcodes, lib_method_opcodes, opcode_dict):
                        method_diff_opcodes = math.fabs(
                            apk_class_methods_dict[apk_method][2]
                            - lib_class_methods_dict[lib_method][2]
                        )
                        # 必须遍历apk类中的所有方法，找出最合适的方法完成匹配
                        if method_diff_opcodes < min_method_diff_opcodes:
                            if (
                                lib_method in methods_match_dict
                            ):  # 说明之前有匹配的方法已经存入methods_match_dict与lib_match_methods
                                apk_match_methods.remove(methods_match_dict[lib_method])
                            methods_match_dict[lib_method] = apk_method
                            apk_match_methods.append(apk_method)
                            min_method_diff_opcodes = method_diff_opcodes

            # 根据apk类中完成匹配的方法确定类是否匹配
            match_methods_weight = 0
            for apk_method in methods_match_dict.values():
                match_methods_weight += apk_class_methods_dict[apk_method][2]
            class_weight = apk_classes_dict[apk_class][2]

            if (
                match_methods_weight / class_weight > class_similar
            ):  # 如果apk类中匹配方法的权重之和 / 类总权重 > 阈值，则类粗粒度匹配
                lib_match_classes.add(lib_class)
                class_match_dict[apk_class] = methods_match_dict

        # 记录apk类与所有lib类粗粒度匹配的详细信息
        if len(class_match_dict) != 0:
            lib_class_match_dict[lib_class] = class_match_dict

    return lib_match_classes, abstract_lib_match_classes, lib_class_match_dict


# 递归的获取当前方法的完整opcode执行序列，算法：在二叉树上的中、右、左遍历（为了避免循环调用对当前方法的影响，删除会循环调用边）
# 注意：并不是调用路径中一个方法只能出现一次，只要不会出现循环调用，可以多次调用同一个方法，比如某个tool方法，设置route_node_list来记录。
def get_method_action(
    node, node_dict, method_action_dict, route_method_set, invoke_length
):
    # 该算法较复杂，需要实际验证是否正确
    method_name = node[: node.rfind("_")]

    cur_action_seq = node_dict[node][0]

    if node.endswith("_1"):  # 说明调用进入了一个新的方法
        if (
            method_name in method_action_dict
        ):  # 如果这个新方法之前已经遍历过了，保存其opcode执行序列结果，直接获取返回
            return method_action_dict[method_name]
        route_method_set.add(method_name)

    invoke_method_name = node_dict[node][1]
    cur_invoke_len = invoke_length

    if (
        invoke_method_name != ""
        and invoke_method_name not in route_method_set
        and invoke_method_name + "_1" in node_dict
        and invoke_length <= 20
    ):  # 调用的新方法不能是当前正在调用路径上的方法
        invoke_length += 1
        seq = get_method_action(
            invoke_method_name + "_1",
            node_dict,
            method_action_dict,
            route_method_set,
            invoke_length,
        )
        if cur_action_seq.endswith(" "):
            cur_action_seq = cur_action_seq + seq
        else:
            cur_action_seq = cur_action_seq + " " + seq

    node_num = int(node[node.rfind("_") + 1 :])
    next_node = method_name + "_" + str(node_num + 1)
    if next_node in node_dict:
        seq = get_method_action(
            next_node, node_dict, method_action_dict, route_method_set, cur_invoke_len
        )
        if cur_action_seq.endswith(" "):
            cur_action_seq = cur_action_seq + seq
        else:
            cur_action_seq = cur_action_seq + " " + seq

    # 方法起始节点的右子树与左子树都遍历完成了，记录该方法完整遍历结果
    if node.endswith("_1"):
        method_action_dict[method_name] = deal_opcode_deq(cur_action_seq)
        route_method_set.remove(method_name)

    return cur_action_seq


# 实现获取指定方法列表中每个方法的完整opcode执行序列
def get_methods_action(method_list, node_dict):
    method_action_dict = {}

    for method in method_list:
        get_method_action(method + "_1", node_dict, method_action_dict, set(), 0)

    return method_action_dict


# 细粒度匹配
def fine_match(apk_obj, lib_obj, lib_class_match_dict, opcode_dict):
    apk_nodes_dict = apk_obj.nodes_dict
    lib_nodes_dict = lib_obj.nodes_dict
    apk_classes_dict = apk_obj.classes_dict
    lib_classes_dict = lib_obj.classes_dict
    # 根据粗粒度匹配结果进行细粒度匹配
    # 1、获取所有需要比较的方法opcode执行序列，并记录到自定methods_action = {method_name: opcode_seq}
    apk_pre_methods = set()
    lib_pre_methods = set()
    for lib_class in lib_class_match_dict:
        for apk_class in lib_class_match_dict[lib_class]:
            apk_pre_methods.update(
                set(list(lib_class_match_dict[lib_class][apk_class].values()))
            )
            lib_pre_methods.update(
                set(list(lib_class_match_dict[lib_class][apk_class].keys()))
            )

    LOGGER.debug("获取方法的完整路径...")
    apk_methods_action = get_methods_action(apk_pre_methods, apk_nodes_dict)
    lib_methods_action = get_methods_action(lib_pre_methods, lib_nodes_dict)
    LOGGER.debug("方法完整路径获取完成...")

    lib_class_match_result = (
        {}
    )  # 键为lib类名，值为列表，包含当前细粒度匹配的apk类、类中细粒度匹配的方法数、类中所有方法细粒度匹配得分之和
    finish_apk_classes = []
    for lib_class in lib_class_match_dict:
        max_match_class_opcodes = 0  # 记录最大得分情况下的库中方法的opcode数量之和
        # 在库类被匹配方法opcode数量相同时，为了找出最佳匹配的apk类，记录类中所有匹配的方法完整opcode序列去重后的差值之和，将方法差值之和最小的视为最佳匹配
        min_class_diff_opcodes = sys.maxsize
        match_apk_class = ""  # 记录最大方法得分对应的lib类名
        # 从apk类对lib类的一对多匹配，筛选出一对一匹配
        for apk_class in lib_class_match_dict[lib_class]:

            if apk_class in finish_apk_classes:
                continue

            match_method_num = 0
            cur_match_class_opcodes = (
                0  # 记录当前库类中细粒度匹配的所有方法opcode数量之和
            )
            cur_class_diff_opcodes = (
                0  # 记录当前匹配类的完整opcode序列操作码数量差值之和
            )
            for lib_method, apk_method in lib_class_match_dict[lib_class][
                apk_class
            ].items():
                apk_method_opcodes = apk_methods_action[apk_method].split(" ")
                lib_method_opcodes = lib_methods_action[lib_method].split(" ")
                if match(apk_method_opcodes, lib_method_opcodes, opcode_dict):
                    # 将当前完成细粒度匹配的lib方法opcode数量加上
                    cur_match_class_opcodes += lib_classes_dict[lib_class][4][
                        lib_method
                    ][2]
                    cur_class_diff_opcodes += math.fabs(
                        (
                            apk_classes_dict[apk_class][3][apk_method][2]
                            - lib_classes_dict[lib_class][4][lib_method][2]
                        )
                    )
                    match_method_num += 1

            if (cur_match_class_opcodes > max_match_class_opcodes) or (
                cur_match_class_opcodes == max_match_class_opcodes
                and cur_class_diff_opcodes < min_class_diff_opcodes
            ):
                max_match_class_opcodes = cur_match_class_opcodes
                min_class_diff_opcodes = cur_class_diff_opcodes
                match_apk_class = apk_class

        # 从lib类对apk类的一对多匹配，筛选出一对一匹配
        if match_apk_class == "":
            continue

        match_info = [
            match_apk_class,
            max_match_class_opcodes,
        ]  # 只考虑细粒度匹配的方法中额的opcode数量
        lib_class_match_result[lib_class] = match_info
        finish_apk_classes.append(match_apk_class)

    return lib_class_match_result


def detect(
    apk_obj: Apk, lib_obj: ThirdLib
) -> Dict[str, Tuple[str, str, str, str, str]]:
    """
    检测apk中包含的库信息
    :param apk_obj: 构建的apk对象
    :param lib: 库名称
    :param lib_obj: 构建的库对象
    :return: 返回检测结果<文件名>:<检测结果> 的映射，检测结果为 (库得分，库得分与方法数壁纸，细粒度匹配的操作码个数，库操作码个数，两个 opcode 数的比)
    """
    if len(lib_obj.classes_dict) == 0:
        return {}

    # 获取库对象中的信息
    # str -> hash, method_num, cls_opcode_num, class_filter, cls_method_info_dict
    lib_opcode_num = lib_obj.lib_opcode_num
    lib_classes_dict = lib_obj.classes_dict

    # 读取opcode及编号，用于后面进行方法匹配
    opcode_dict = get_opcode_coding("conf/opcodes_encoding.txt")

    # 用于存放检测结果
    result: Dict[str, Tuple[str, str, str, str, str]] = {}
    # 需要统计的信息
    # 布隆过滤器平均过滤率
    avg_filter_rate = 0
    # 检测库平均用时
    avg_time = 0

    """
    THRESHOLD

    计算 TPL 与 apk 之间 pre-match 的 threshold
    """
    # 通过过滤器为库中的每个类找出app中的潜在匹配类集合
    filter_result = pre_match(apk_obj, lib_obj)
    pre_match_opcodes = 0
    for lib_class in filter_result:
        # 记录存在预匹配应用程序类的库类opcode数量之和
        if len(lib_classes_dict[lib_class]) == 2:  # 说明是接口或抽象类
            pre_match_opcodes += lib_classes_dict[lib_class][0] * abstract_method_weight
        else:
            pre_match_opcodes += lib_classes_dict[lib_class][2]
        LOGGER.debug("预匹配lib_class: %s", lib_class)
        # if "pre" in lib_obj.lib_name:
        #     LOGGER.info("预匹配lib_class: %s", lib_class)
        for apk_class in filter_result[lib_class]:
            LOGGER.debug("apk_class: %s", apk_class)
            # if "pre" in lib_obj.lib_name:
            #     LOGGER.info("apk_class: %s", apk_class)
        LOGGER.debug("-------------------------------")
        # if "pre" in lib_obj.lib_name:
        #     LOGGER.info("-------------------------------")

    # 根据预匹配结果判断是否不包含
    pre_match_rate = pre_match_opcodes / lib_opcode_num
    if pre_match_rate < lib_similar:
        LOGGER.debug(
            "预匹配失败库：%s，预匹配率为：%f", lib_obj.lib_name, pre_match_rate
        )
        if "pre" in lib_obj.lib_name:
            LOGGER.info(
                "预匹配失败库：%s，预匹配率为：%f", lib_obj.lib_name, pre_match_rate
            )
        return {}

    if "pre" in lib_obj.lib_name:
        LOGGER.info(
            "预匹配成功库：%s，预匹配率为：%f", lib_obj.lib_name, pre_match_rate
        )
    # avg_filter_rate += filter_rate
    # LOGGER.debug("filter_rate: %f", filter_rate)
    # LOGGER.debug("filter_effect: %f", filter_effect)

    # 进行粗粒度匹配
    lib_match_classes, abstract_lib_match_classes, lib_class_match_dict = coarse_match(
        apk_obj, lib_obj, filter_result, opcode_dict
    )

    # DEBUG
    for lib_class in lib_class_match_dict:
        if len(lib_class_match_dict[lib_class]) > 1:
            LOGGER.debug("粗粒度匹配lib_class: %s", lib_class)
            for apk_class in lib_class_match_dict[lib_class]:
                LOGGER.debug("apk_class: %s", apk_class)
                for lib_method in lib_class_match_dict[lib_class][apk_class]:
                    LOGGER.debug(
                        "库类函数%s → 应用程序类函数%s",
                        lib_method,
                        lib_class_match_dict[lib_class][apk_class][lib_method],
                    )
        LOGGER.debug("-------------------------------")

    # 计算库中抽象类或接口的匹配得分
    abstract_match_opcodes = 0
    for abstract_class in abstract_lib_match_classes:
        abstract_match_opcodes += (
            lib_classes_dict[abstract_class][0] * abstract_method_weight
        )

    # 计算lib粗粒度匹配得分
    lib_coarse_match_opcode_num = 0
    for lib_class in lib_match_classes:
        lib_coarse_match_opcode_num += lib_classes_dict[lib_class][2]
    lib_coarse_match_opcode_num += abstract_match_opcodes

    lib_coarse_match_rate = lib_coarse_match_opcode_num / lib_opcode_num
    LOGGER.debug("lib粗粒度匹配的类中所有opcode数量：%d", lib_coarse_match_opcode_num)
    LOGGER.debug("lib粗粒度率：%f", lib_coarse_match_rate)
    LOGGER.debug(
        "库中匹配的类数：%d", len(lib_match_classes) + len(abstract_lib_match_classes)
    )
    LOGGER.debug("库中所有参与匹配的类数：%d", len(lib_classes_dict))

    # 根据粗粒度匹配结果判断是否不包含
    if lib_coarse_match_rate < lib_similar:
        LOGGER.debug(
            "粗粒度匹配失败库：%s，粗粒度匹配率为：%f",
            lib_obj.lib_name,
            lib_coarse_match_rate,
        )
        if "pre" in lib_obj.lib_name:
            LOGGER.info(
                "粗粒度匹配失败库：%s，粗粒度匹配率为：%f",
                lib_obj.lib_name,
                lib_coarse_match_rate,
            )
        return {}

    if "pre" in lib_obj.lib_name:
        LOGGER.info(
            "粗粒度匹配成功库：%s，粗粒度匹配率为：%f",
            lib_obj.lib_name,
            lib_coarse_match_rate,
        )
    # 进行细粒度匹配
    lib_class_match_result = fine_match(
        apk_obj, lib_obj, lib_class_match_dict, opcode_dict
    )
    for lib_class in lib_class_match_result:
        LOGGER.debug(
            "细粒度：库类%s → 应用程序类%s",
            lib_class,
            lib_class_match_result[lib_class][0],
        )
    LOGGER.debug("库中细粒度无匹配的类如下：")
    for lib_class in lib_classes_dict:
        if (
            lib_class not in abstract_lib_match_classes
            and lib_class not in lib_class_match_result
        ):
            LOGGER.debug("lib_class: %s", lib_class)

    # 根据细粒度匹配结果，统计匹配的方法数之和以及所有方法细粒度匹配得分之和作为lib匹配得分
    # 每个方法包含的内容多少不一样，大方法匹配与小方法匹配的意义也不一样，所以，统计方法匹配个数没有意义。
    final_match_opcodes = 0
    for lib_class in lib_class_match_result:
        final_match_opcodes += lib_class_match_result[lib_class][1]
    final_match_opcodes += abstract_match_opcodes

    # 根据待检测的库是否为纯接口库来调整库相似度阈值
    min_lib_match = lib_similar
    if lib_obj.interface_lib:
        min_lib_match = 1.0

    # print("当前库为：", lib_obj.lib_name)
    temp_list = [
        final_match_opcodes,
        lib_opcode_num,
        final_match_opcodes / lib_opcode_num,
    ]
    if final_match_opcodes / lib_opcode_num >= min_lib_match:
        LOGGER.debug("包含")
        result[lib_obj.lib_name] = temp_list
    LOGGER.info(
        (
            "细粒度匹配库 %s，匹配率：%f，"
            + (
                "成功"
                if final_match_opcodes / lib_opcode_num >= min_lib_match
                else "失败"
            )
        ),
        lib_obj.lib_name,
        final_match_opcodes / lib_opcode_num,
    )

    return result


# 同时分析一个库的不同版本
def detect_lib(
    libs_name: List[str],
    apk_obj: Apk,
    methodes_jar: Dict[str, str],
    global_jar_dict: Dict[str, List[str]],
    global_finished_jar_dict: Dict[str, Tuple[str, float]],
    global_running_jar_list: List[str],
    shared_lock_libs,
    global_lib_info_dict: Dict[str, ThirdLib],
    loop_dependence_libs,
) -> Tuple[Dict[Apk, Tuple[str, str, str, str, str]], bool]:
    """
    :libs_name: List[str]. 记录同个包不同版本的库名
    :global_jar_dict: Dict[str, List[str]]. 记录同个包不同版本 <包名>:<文件名> 的映射
    :global_finished_jar_dict: Dict[str, Tuple[str, float]]. 记录 <文件名>:<检测结果> 的映射，检测结果为 （库包名，库得分）
    :global_running_jar_list: List[str]. 记录正在检测的库
    :global_lib_info_dict: Dict[str, ThirdLib]. 记录 <文件名>.dex:<库对象>

    检测 apk_obj 中包含的 TPL 信息，使用 methodes_jar, global_lib_info_dict, loop_dependence_libs


    Li: Seems to be the core detection function
    """
    result = {}  # 记录当前库所有版本检测结果
    flag = True  # 记录当前库是成功检测完成，还是存在尚未检测的依赖库，目前无法检测

    lib_versions_dict = {}
    libs_name.reverse()
    for lib in libs_name:
        LOGGER.debug("开始检测库：%s", lib)

        cur_libs = set()
        # 处理库依赖关系
        lib_obj = get_lib_info(
            lib,
            methodes_jar,
            cur_libs,
            global_jar_dict,
            global_finished_jar_dict,
            global_running_jar_list,
            shared_lock_libs,
            global_lib_info_dict,
            loop_dependence_libs,
        )
        if lib_obj == None:
            LOGGER.debug("存在尚未分析完成的依赖库！")
            flag = False
            return result, flag
        lib_versions_dict[lib] = lib_obj

    for lib in lib_versions_dict:
        result.update(detect(apk_obj, lib_versions_dict[lib]))

    return result, flag


# 将库操作码数量占比最大的视为真实库版本
def get_lib_version(result_dict):
    max_lib = ""
    opcode_rate = 0

    for lib in result_dict:
        lib_name = lib[: lib.rfind(".")]
        if result_dict[lib][2] > opcode_rate:
            max_lib = lib_name
            opcode_rate = result_dict[lib][2]
        elif result_dict[lib][2] == opcode_rate:
            max_lib += " and " + lib_name

    final_lib = max_lib

    return [final_lib, opcode_rate]


# 实现子进程检测
def sub_detect_lib(
    process_name,
    global_jar_dict: Dict[str, List[str]],
    global_finished_jar_dict: Dict[str, Tuple[str, float]],
    global_running_jar_list: List[str],
    shared_lock_libs,
    global_libs_info_dict: Dict[str, Tuple[str, str, str, str, str]],
    shared_lock_libs_info,
    apk_obj: Apk,
    methodes_jar: Dict[str, str],
    global_lib_info_dict: Dict[str, ThirdLib],
    loop_dependence_libs: List[str],
):
    """
    :global_jar_dict: Dict[str, List[str]]. 记录同个包不同版本 <包名>:<文件名> 的映射
    :global_finished_jar_dict: Dict[str, Tuple[str, float]]. 记录 <文件名>:<检测结果> 的映射，检测结果为 （库包名，库得分）
    :global_running_jar_list: List[str]. 记录正在检测的库
    :global_libs_info_dict: Dict[str, Tuple[str, str, str]]. 记录 <文件名>:<检测结果> 的映射，检测结果为 (库得分，库得分与方法数壁纸，细粒度匹配的操作码个数，库操作码个数，两个 opcode 数的比)

    检测 apk_obj 中包含的 TPL 信息，使用 methodes_jar, global_lib_info_dict, loop_dependence_libs

    global_jar_dict.keys() 对应不同的包。每个包不同版本被归类到统一项
    """

    while len(global_jar_dict) > 0:
        shared_lock_libs.acquire()
        if len(global_jar_dict) > 0:
            first_key = global_jar_dict.keys()[0]
            libs = global_jar_dict.pop(first_key)
            global_running_jar_list.append(first_key)
            shared_lock_libs.release()
        else:
            shared_lock_libs.release()
            break

        # 对同一个库的所有版本进行检测,并返回检测结果字典（键为jar名，值为四个值）
        result, flag = detect_lib(
            libs,
            apk_obj,
            methodes_jar,
            global_jar_dict,
            global_finished_jar_dict,
            global_running_jar_list,
            shared_lock_libs,
            global_lib_info_dict,
            loop_dependence_libs,
        )

        if not flag:  # 说明当前库由于存在尚未完成的依赖库，未执行检测
            shared_lock_libs.acquire()
            global_jar_dict[first_key] = libs
            global_running_jar_list.remove(first_key)
            shared_lock_libs.release()
            continue

        if len(result) != 0:  # 说明库被检测到存在
            # 将当前库所有版本检测结果信息放入全局字典
            shared_lock_libs_info.acquire()
            for lib in sorted(result):
                global_libs_info_dict[lib] = result[lib]
            shared_lock_libs_info.release()

            lib_version_info = get_lib_version(result)
            # 键库检测结果版本写入global_finished_jar_dict
            shared_lock_libs.acquire()
            global_finished_jar_dict[first_key] = lib_version_info
            global_running_jar_list.remove(first_key)
            shared_lock_libs.release()
        else:  # 说明库被检测到不存在
            shared_lock_libs.acquire()
            global_running_jar_list.remove(first_key)
            shared_lock_libs.release()


def sub_find_loop_dependence_libs(
    libs, dependence_relation, loop_dependence_libs, shared_lock_loop_libs
):
    """
    实现子线程：根据依赖关系确定循环依赖库
    使用 nx.DiGraph 根据 (caller, callee) 建图、找环
    添加有环节点 method 到 loop_dependence_libs
    """
    DG = nx.DiGraph(list(dependence_relation))
    for lib_name in libs:
        try:
            nx.find_cycle(DG, source=lib_name)
            shared_lock_loop_libs.acquire()
            if lib_name not in loop_dependence_libs:
                loop_dependence_libs.append(lib_name)
            shared_lock_loop_libs.release()
        except Exception:
            pass


def search_libs_in_app(
    lib_dex_folder: str, apk_folder=None, output_folder="outputs", processes=None
):
    """
    :param lib_dex_folder: 库 dex 文件夹，保存全部 TPL
    :apk_folder: 待测 apk
    :output_folder: 输出文件夹
    :processes: 设置并发进程数

    1. 检查 output 中 <apk>.txt 标记为已完成 apk
    2. 查找 lib_dex_folder，逐个反编译产生 ThirdLib instance，记录 method-.dex 映射到 methodes_jar.txt
    3. 根据 methodes_jar 判定调用的函数是否在检测范围之中。去除 loop
    4. 对每个 apk 反编译并逐 TPL 检测，跳过已经存在结果的 apk

    这三个路径必须存在
    """
    # 获取分析完成的apk集合
    finish_apks = [apk[: apk.rfind(".")] for apk in os.listdir(output_folder)]
    # 设置分析的cpu数量上限
    thread_num = processes if processes != None else max_thread_num

    print("num of apk had been analyzed: ", len(finish_apks), "IGNORING")
    LOGGER.warning("IGNORING analyzed apks: {}".format(finish_apks))
    print(f"thread num = {thread_num}")
    LOGGER.info("分析最大使用的cpu数：%d", thread_num)

    LOGGER.debug("开始提取所有库信息...")

    time_start = datetime.datetime.now()
    libs = os.listdir(lib_dex_folder)
    random.shuffle(libs)

    """
    :global_lib_info_dict: Dict[str, ThirdLib] . 全局共享变量，用作 cache。记录每个库的反编译结果。eg. {<filename>.dex: Object}
    :shared_lock_lib_info: Lock . lib_info_dict 的锁，草并不是 lock 这玩意的，是 lock methods_jar.txt 的
    :global_dependence_relation: List[Tuple] . 全局共享变量，记录所有分析库中的依赖关系（包名）。eg. [(<caller pkg>, <callee pkg>), (<>,<>),...]
    :global_dependence_libs: List[str] . 全局共享变量，记录所有分析库中存在依赖关系的库列表。eg. [<caller>, <callee>]
    :shared_lock_dependence_info: Lock . dependence_relation 的锁
    :loop_dependence_libs: List[str] . 存在循环依赖的库列表。根据前面的共享变量算出来的 eg.  ['ezvcard', 'org.slf4j','ch.qos.logback.classic']
    :shared_lock_loop_libs: Lock . loop_dependence_libs 的锁
    """

    global_lib_info_dict: Dict[str, ThirdLib] = multiprocessing.Manager().dict()
    shared_lock_lib_info = multiprocessing.Manager().Lock()
    global_dependence_relation: List[Tuple[str, str]] = multiprocessing.Manager().list()
    global_dependence_libs: List[str] = multiprocessing.Manager().list()
    shared_lock_dependence_info = multiprocessing.Manager().Lock()
    loop_dependence_libs: List[str] = multiprocessing.Manager().list()
    shared_lock_loop_libs = multiprocessing.Manager().Lock()

    decompile_thread_num = thread_num if thread_num <= len(libs) else len(libs)

    # 构建当前方法与所属库映射文件，用于后续分析依赖库
    if os.path.exists("conf/methodes_jar.txt"):
        os.remove("conf/methodes_jar.txt")

    processes_list_method_maps = (
        []
    )  # 用于 method maps 的 process list，存放所有的子进程

    for sub_libs in split_list_n_list(libs, decompile_thread_num):
        thread = multiprocessing.Process(
            target=sub_method_map_decompile,
            args=(lib_dex_folder, sub_libs, global_lib_info_dict, shared_lock_lib_info),
        )

        processes_list_method_maps.append(thread)

    # 开启所有反编译子进程
    for thread in processes_list_method_maps:
        thread.start()

    # 等待所有反编译子进程运行结束
    for thread in processes_list_method_maps:
        thread.join()

    # 定义多进程将所有待检测的库全部反编译，并提取库反编译得到的各类信息
    methodes_jar = get_methods_jar_map()
    processes_list_decompile = []  # 用于 decompile 的 process list，存放所有的子进程
    for sub_libs in split_list_n_list(libs, decompile_thread_num):
        thread = multiprocessing.Process(
            target=sub_decompile_lib,
            args=(
                lib_dex_folder,
                sub_libs,
                global_lib_info_dict,
                shared_lock_lib_info,
                methodes_jar,
                global_dependence_relation,
                global_dependence_libs,
                shared_lock_dependence_info,
                loop_dependence_libs,
            ),
        )

        processes_list_decompile.append(thread)

    # 开启所有反编译子进程
    for thread in processes_list_decompile:
        thread.start()

    # 等待所有反编译子进程运行结束
    for thread in processes_list_decompile:
        thread.join()

    print("All TPL information extracted ...")

    # 定义多线程根据库依赖关系找出所有存在循环依赖的库，后续对于这些库的检测不考虑依赖库
    if len(global_dependence_libs) != 0:
        dependence_deal_thread_num = (
            thread_num
            if thread_num <= len(global_dependence_libs)
            else len(global_dependence_libs)
        )

        # print("处理依赖库")
        processes_list_libs_dependence = []
        for sub_libs in split_list_n_list(
            global_dependence_libs, dependence_deal_thread_num
        ):
            thread = multiprocessing.Process(
                target=sub_find_loop_dependence_libs,
                args=(
                    sub_libs,
                    global_dependence_relation,
                    loop_dependence_libs,
                    shared_lock_loop_libs,
                ),
            )

            processes_list_libs_dependence.append(thread)

        # 开启所有反编译子进程
        for thread in processes_list_libs_dependence:
            thread.start()

        # 等待所有反编译子进程运行结束
        for thread in processes_list_libs_dependence:
            thread.join()

    time_end = datetime.datetime.now()
    LOGGER.debug("所有库信息提取完成, 用时：%d", (time_end - time_start).seconds)

    for apk in os.listdir(apk_folder):

        if apk in finish_apks:
            continue

        print("start analyzing: ", apk)
        LOGGER.info("开始分析：%s", apk)
        apk_time_start = datetime.datetime.now()

        try:
            apk_obj = Apk(apk_folder + "/" + apk)
        except Exception as e:
            LOGGER.error("apk文件解析失败：%s", os.path.join(apk_folder, apk), e)
            continue

        # 定义全局分析完成的jar名字典（键为库的唯一标志名，值为该库被检测出的具体版本，(包名'.', ' and ', acc)）
        global_finished_jar_dict: Dict[str, Tuple[str, float]] = (
            multiprocessing.Manager().dict()
        )
        # 定义全局正在分析列表（包含每一个正在分析的库的唯一标识）
        global_running_jar_list: List[str] = multiprocessing.Manager().list()
        # 定义全局检测结果详细信息列表（记录每个被检测为包含的库版本详细信息，用于最后输出）
        global_libs_info_dict: Dict = multiprocessing.Manager().dict()

        # 为三个全局的数据结构定义一把锁
        shared_lock_libs = multiprocessing.Manager().Lock()
        shared_lock_libs_info = multiprocessing.Manager().Lock()

        # 定义全局待分析所有jar名字典（键为库唯一标识名，值为列表，包含该库所有版本jar名）测试完成的包会删除
        global_jar_dict: Dict[str, List[str]] = (
            multiprocessing.Manager().dict()
        )  # pkg -> [filenames, ...]
        for jar in os.listdir(lib_dex_folder):
            lib_name = get_lib_name(jar)
            if lib_name != "":
                libs_list = global_jar_dict.get(lib_name, [])
                libs_list.append(jar)
                global_jar_dict[lib_name] = libs_list

        # processes = 1
        # 定义多进程检测
        processes_list_detect = []
        detect_thread_num = (
            thread_num if thread_num <= len(global_jar_dict) else len(global_jar_dict)
        )
        for i in range(1, detect_thread_num + 1):
            process_name = "子进程 " + str(i)
            thread = multiprocessing.Process(
                target=sub_detect_lib,
                args=(
                    process_name,
                    global_jar_dict,
                    global_finished_jar_dict,
                    global_running_jar_list,
                    shared_lock_libs,
                    global_libs_info_dict,
                    shared_lock_libs_info,
                    apk_obj,
                    methodes_jar,
                    global_lib_info_dict,
                    loop_dependence_libs,
                ),
            )
            processes_list_detect.append(thread)

        # 开启所有子进程
        for thread in processes_list_detect:
            thread.start()

        # 主进程定期检测当前分析完成的库数量，并按百分制进度条显示（per apk）
        time_sec = 0
        all_libs_num = len(os.listdir(lib_dex_folder))
        LOGGER.info("本次分析的库数量为：%d", all_libs_num)
        time.sleep(1)
        finish_num = all_libs_num - len(global_jar_dict) - len(global_running_jar_list)
        while finish_num < all_libs_num:
            finish_rate = int(finish_num / all_libs_num * 100)
            print(
                "\r"
                + "current analysis: "
                + "▇" * (int(finish_rate / 2))
                + str(finish_rate)
                + "%",
                end="",
            )
            time.sleep(1)
            time_sec += 1
            finish_num = (
                all_libs_num - len(global_jar_dict) - len(global_running_jar_list)
            )
        print(
            "\r"
            + "current analysis: "
            + "▇" * (int(finish_num / all_libs_num * 100 / 2))
            + str(int(finish_num / all_libs_num * 100))
            + "%",
            end="",
        )
        print("")

        # 等待所有子进程运行结束
        for thread in processes_list_detect:
            thread.join()

        # 输出检测结果信息
        LOGGER.info(
            "-------------------------------------------------------------------"
        )
        LOGGER.info("包含的所有库详细检测信息如下：")
        for lib in global_libs_info_dict:
            # 库得分  库得分与方法数比值  细粒度匹配的操作码个数  库的操作码个数  前面两操作码个数比值
            # Logger.error("%s  %s  %s  %s  %s", "库得分", "库得分与方法数比值", "细粒度匹配的操作码个数", "库的操作码个数", "前面两操作码个数比值")
            LOGGER.info(
                "%s  :  %f   %f   %f",
                lib,
                global_libs_info_dict[lib][0],
                global_libs_info_dict[lib][1],
                global_libs_info_dict[lib][2],
            )
        LOGGER.info(
            "-------------------------------------------------------------------"
        )
        # 输出apk分析时长
        apk_time_end = datetime.datetime.now()
        apk_time = (apk_time_end - apk_time_start).seconds
        with open(output_folder + "/" + apk + ".txt", "w", encoding="utf-8") as result:
            for lib in sorted(global_finished_jar_dict.keys()):
                result.write("lib: " + global_finished_jar_dict[lib][0] + "\n")
                result.write(
                    "similarity: " + str(global_finished_jar_dict[lib][1]) + "\n\n"
                )
            result.write("time: " + str(apk_time) + "s")

        LOGGER.info("当前apk分析时长：%d（单位秒）", apk_time)


def sub_detect_apk(
    process_name,
    lib_obj,
    apk_folder,
    global_apk_list,
    global_result_dict,
    share_lock_apk,
    share_lock_result,
):
    while len(global_apk_list) > 0:
        share_lock_apk.acquire()
        if len(global_apk_list) > 0:
            apk = global_apk_list.pop()
            share_lock_apk.release()
        else:
            share_lock_apk.release()
            break

        apk_obj = Apk(apk_folder + "/" + apk)
        result = detect(apk_obj, lib_obj)

        if len(result) != 0:
            share_lock_result.acquire()
            global_result_dict[apk] = str(result[lib_obj.lib_name][2])
            share_lock_result.release()


def search_lib_in_app(
    lib_dex_folder=None, apk_folder=None, output_folder="outputs", processes=None
):
    # 设置分析的cpu数量
    thread_num = processes if processes != None else max_thread_num
    LOGGER.info("分析使用的cpu数：%d", thread_num)

    LOGGER.debug("开始提取库信息...")
    time_start = datetime.datetime.now()

    lib_path = ""
    for lib in os.listdir(lib_dex_folder):
        lib_path = lib_dex_folder + "/" + lib
    lib_obj = ThirdLib(lib_path)

    time_end = datetime.datetime.now()
    LOGGER.debug("库信息提取完成, 用时：%d", (time_end - time_start).seconds)

    # 定义全局待分析的apk里列表
    global_apk_list = multiprocessing.Manager().list()
    for apk in os.listdir(apk_folder):
        global_apk_list.append(apk)
    # 定义全局分析结果字典，键为apk名称，值为检测为包含的情况下，库操作码占比值，也可理解为相似度值
    global_result_dict = multiprocessing.Manager().dict()
    # 定义结构锁
    share_lock_apk = multiprocessing.Manager().Lock()
    share_lock_result = multiprocessing.Manager().Lock()

    # 定义apk级多线程检测
    print("Start detection ...")
    processes_list_detect = []
    for i in range(1, thread_num + 1):
        process_name = str(i)
        thread = multiprocessing.Process(
            target=sub_detect_apk,
            args=(
                process_name,
                lib_obj,
                apk_folder,
                global_apk_list,
                global_result_dict,
                share_lock_apk,
                share_lock_result,
            ),
        )
        processes_list_detect.append(thread)

    # 开启所有子进程
    for thread in processes_list_detect:
        thread.start()

    # 主进程定期检测当前分析完成的库数量，并按百分制进度条显示
    time_sec = 0
    all_apks_num = len(os.listdir(apk_folder))
    LOGGER.info("本次分析的apk数量为：%d", all_apks_num)
    time.sleep(1)
    finish_num = all_apks_num - len(global_apk_list)
    while finish_num < all_apks_num:
        finish_rate = int(finish_num / all_apks_num * 100)
        print(
            "\r"
            + "current analysis: "
            + "▇" * (int(finish_rate / 2))
            + str(finish_rate)
            + "%",
            end="",
        )
        time.sleep(1)
        time_sec += 1
        finish_num = all_apks_num - len(global_apk_list)
    print(
        "\r"
        + "current analysis: "
        + "▇" * (int(finish_num / all_apks_num * 100 / 2))
        + str(int(finish_num / all_apks_num * 100))
        + "%",
        end="",
    )
    print("")

    # 等待所有子进程运行结束
    for thread in processes_list_detect:
        thread.join()

    # 日志中输入检测结果
    # 将所有检测结果写入文件
    # print("global_result_dict: ", global_result_dict)
    with open(output_folder + "/results.txt", "w", encoding="utf-8") as result:
        result.write("apk名称     库名称     相似度得分\n")
        for k in sorted(global_result_dict.keys()):
            result.write(
                k + "   " + lib_obj.lib_name + "   " + global_result_dict[k] + "\n"
            )

    # 输出apk分析时长
    time_end = datetime.datetime.now()
    LOGGER.info("检测时长：%d（单位秒）", (time_end - time_start).seconds)
