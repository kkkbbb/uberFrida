# Uber请求生成器 - Android Kotlin版本

这是一个将原始Rust代码转换为Android Kotlin实现的项目，使用数据类映射JSON结构并保留原有的层级结构。

## 项目结构

```
├── UberRequestGenerator.kt      # 使用Gson的版本
├── UberRequestAndroid.kt        # 使用Kotlin序列化的Android版本
├── build.gradle.kts            # 构建配置
└── README.md                   # 本文档
```

## 主要特性

### 1. 完整的数据类映射
- 使用Kotlin数据类映射复杂的JSON结构
- 保留原始JSON的所有层级关系
- 支持可选字段和默认值

### 2. 两种实现方式
- **Gson版本** (`UberRequestGenerator.kt`): 适用于一般Kotlin项目
- **Kotlin序列化版本** (`UberRequestAndroid.kt`): 适用于Android项目，性能更好

### 3. 核心数据类

```kotlin
// 主请求数据类
data class UberRequest(
    val registerUrl: String,
    val pack1: Pack1,
    val pack2: Pack2
)

// 设备数据类
data class DeviceData(
    val androidId: String,
    val batteryLevel: Double,
    val deviceIds: DeviceIds,
    // ... 其他字段
)

// 表单数据类
data class FormAnswer(
    val flowType: String,
    val screenAnswers: List<ScreenAnswer>,
    val deviceData: String,
    val firstPartyClientID: String,
    val standardFlow: Boolean
)
```

## 使用方法

### 基本用法

```kotlin
// 生成请求
val request = UberRequestGenerator.generateRequest(
    firstPartyClientId = "your_client_id",
    appDeviceId = "your_app_device_id", 
    coldLaunchId = "your_cold_launch_id"
)

// 转换为JSON字符串
val jsonString = UberRequestGenerator.toJson(request)
println(jsonString)
```

### 更新验证数据

```kotlin
// 更新验证码和验证器
val updatedRequest = UberRequestGenerator.updateVerificationData(
    request = request,
    sessionVerificationCode = "123456",
    codeVerifier = "actual_code_verifier", 
    registerUrl = "https://example.com/register"
)
```

### JSON解析

```kotlin
// 从JSON字符串解析
val parsedRequest = UberRequestGenerator.fromJson(jsonString)
```

## Android集成

### 1. 添加依赖 (build.gradle.kts)

```kotlin
plugins {
    kotlin("plugin.serialization") version "1.9.0"
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
    // 或者使用Gson
    implementation("com.google.code.gson:gson:2.10.1")
}
```

### 2. 在Android项目中使用

```kotlin
class UberApiService {
    
    fun generateUberRequest(
        clientId: String,
        deviceId: String,
        launchId: String
    ): UberRequest {
        return UberRequestGenerator.generateRequest(
            firstPartyClientId = clientId,
            appDeviceId = deviceId,
            coldLaunchId = launchId
        )
    }
    
    suspend fun sendRequest(request: UberRequest) {
        // 使用OkHttp或Retrofit发送请求
        val pack1Json = UberRequestGenerator.toJson(request.pack1)
        val pack2Json = UberRequestGenerator.toJson(request.pack2)
        
        // 发送Pack1请求
        httpClient.post(request.pack1.url) {
            headers {
                request.pack1.headers.forEach { (key, value) ->
                    append(key, value)
                }
            }
            setBody(pack1Json)
        }
        
        // 发送Pack2请求
        // ...
    }
}
```

## 数据结构对比

### 原始Rust JSON结构
```json
{
  "register_url": "",
  "pack1": {
    "url": "https://cn-geo1.uber.com/rt/silk-screen/submit-form",
    "headers": { ... },
    "body": {
      "formContainerAnswer": {
        "inAuthSessionID": "xxx",
        "formAnswer": { ... }
      }
    }
  },
  "pack2": { ... }
}
```

### Kotlin数据类映射
```kotlin
UberRequest(
    registerUrl = "",
    pack1 = Pack1(
        url = "https://cn-geo1.uber.com/rt/silk-screen/submit-form",
        headers = mapOf(...),
        body = Pack1Body(
            formContainerAnswer = FormContainerAnswer(
                inAuthSessionID = "xxx",
                formAnswer = FormAnswer(...)
            )
        )
    ),
    pack2 = Pack2(...)
)
```

## 运行测试

```bash
# 编译项目
./gradlew build

# 运行测试
./gradlew run
```

## 技术细节

### 随机数据生成
- 使用`UUID.randomUUID()`生成唯一标识符
- 使用`Random.nextInt()`生成随机字节数组
- 保持与原始Rust实现相同的数据格式

### 时间戳处理
- 使用`System.currentTimeMillis()`获取当前时间戳
- 添加随机数后缀以增加唯一性

### 设备信息
- 模拟Android设备信息
- 包含电池状态、网络信息等详细数据
- 支持自定义设备参数

## 注意事项

1. **序列化选择**: Android项目推荐使用Kotlin序列化，性能更好且类型安全
2. **内存优化**: 大型JSON对象建议使用流式解析
3. **网络请求**: 建议使用Retrofit + OkHttp进行网络请求
4. **错误处理**: 添加适当的异常处理和重试机制

## 许可证

本项目基于MIT许可证开源。