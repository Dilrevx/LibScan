# 统一方法名表示形式
def valid_method_name(method_full_name: str):
    """
    In: eg. 'Lorg/jsoup/Connection$KeyVal; value (Ljava/lang/String;)Lorg/jsoup/Connection$KeyVal;'

    Validate method name. Remove the `class` identifier L, elimate / -> ., white space
    and swap the ; between classname, method descriptor to .
    """

    method_full_name = method_full_name.replace(" ", "")
    class_name = method_full_name[1 : method_full_name.find(";")].replace(
        "/", "."
    )  # com.google.android.gms.internal.bn.onPause()V
    other = method_full_name[method_full_name.find(";") + 1 :]  #
    return class_name + "." + other


def read_file_to_list(path, mode="r", encoding="utf-8"):
    """
    almost same as readlines, remove `\\n`. Also wraps with open
    """
    lines_list = []
    with open(path, mode, encoding=encoding) as file:
        for line in file.readlines():
            lines_list.append(line.strip("\n"))
    return lines_list


def split_list_n_list(origin_list, n):
    """
    将一个列表均分为n个
    """
    if len(origin_list) % n == 0:
        cnt = len(origin_list) // n
    else:
        cnt = len(origin_list) // n + 1

    for i in range(0, n):
        yield origin_list[i * cnt : (i + 1) * cnt]


def deal_opcode_deq(opcode_seq: str) -> str:
    """
    对opcode seq ("op1 op2 ...")去重处理，依然返回 seq，不保证顺序
    """

    new_seq = ""
    for seq in set(opcode_seq.split(" ")):
        new_seq = new_seq + seq + " "
    return new_seq[:-1]


# 将时间转换为毫秒
def toMillisecond(start_time, end_time):
    return (end_time - start_time).seconds * 1000 + (
        end_time - start_time
    ).microseconds / 1000
