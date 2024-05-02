methods_jar.txt: 生成的文件。<方法>:\<dex文件名> 的映射文件，用于后续分析依赖库
例如：
```
com.fasterxml.jackson.databind.AbstractTypeResolver.findTypeMapping(Lcom/fasterxml/jackson/databind/DeserializationConfig;Lcom/fasterxml/jackson/databind/JavaType;)Lcom/fasterxml/jackson/databind/JavaType;:jackson-databind-2.9.10.7.dex
```

lib_name_map.csv: 是程序唯一的查询 文件名 - 包名 映射的地方。用于指定库的版本信息，格式为\<库名>,\<版本>,\<版本号>，