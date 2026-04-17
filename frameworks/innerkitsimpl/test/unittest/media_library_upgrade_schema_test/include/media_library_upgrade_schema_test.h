/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEDIA_LIBRARY_UPGRADE_SCHEMA_TEST_H
#define MEDIA_LIBRARY_UPGRADE_SCHEMA_TEST_H

#include <gtest/gtest.h>
#include <string>
#include <memory>
#include <vector>
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_open_callback.h"

namespace OHOS::Media {

/**
 * @struct TestResult
 * @brief 测试结果结构体
 * 
 * 该结构体用于封装Schema一致性测试的结果信息，
 * 包括Schema对比结果和任务配置检查结果。
 */
struct TestResult {
    /** @brief 结果文件路径 */
    std::string resultFilePath;
    
    /** @brief Schema是否一致 */
    bool isConsistent;
    
    /** @brief Schema差异信息列表 */
    std::vector<std::string> differences;
    
    /** @brief 任务配置检查是否通过 */
    bool taskCheckPassed;
    
    /** @brief 任务配置检查错误信息列表 */
    std::vector<std::string> taskCheckErrors;
    
    /** @brief 索引详细信息（仅存在于db1或db2的索引SQL） */
    std::vector<std::string> indexDetails;
    
    /** @brief 触发器详细信息（仅存在于db1或db2的触发器SQL） */
    std::vector<std::string> triggerDetails;
};

/**
 * @class UpgradeSchemaTest
 * @brief 媒体库升级Schema一致性测试类
 * 
 * 该类用于测试媒体库数据库在创建和升级两种场景下的Schema一致性。
 * 主要验证数据库表结构、索引、触发器等是否保持一致。
 */
class UpgradeSchemaTest : public testing::Test {
public:
    /**
     * @brief 测试用例初始化函数
     */
    static void SetUpTestCase();

    /**
     * @brief 测试用例清理函数
     */
    static void TearDownTestCase();

    /**
     * @brief 单个测试用例初始化函数
     */
    void SetUp();

    /**
     * @brief 单个测试用例清理函数
     */
    void TearDown();

    /**
     * @brief 获取测试数据库路径
     * @param dbName 数据库名称
     * @return 测试数据库完整路径
     */
    static std::string GetTestDbPath(const std::string& dbName);

    /**
     * @brief 删除测试数据库文件
     * @param dbPath 数据库文件路径
     */
    static void RemoveTestDb(const std::string& dbPath);
};

/**
 * @class TestRdbCreateCallback
 * @brief 测试用数据库创建回调类
 * 
 * 该类用于模拟数据库创建场景的回调处理。
 */
class TestRdbCreateCallback : public NativeRdb::RdbOpenCallback {
public:
    /**
     * @brief 数据库创建时的回调函数
     * @param rdbStore 数据库存储对象引用
     * @return 成功返回NativeRdb::E_OK
     */
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    /**
     * @brief 数据库升级时的回调函数
     * @param rdbStore 数据库存储对象引用
     * @param oldVersion 旧版本号
     * @param newVersion 新版本号
     * @return 成功返回NativeRdb::E_OK
     */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
};

/**
 * @class TestRdbUpgradeCallback
 * @brief 测试用数据库升级回调类
 * 
 * 该类用于模拟数据库升级场景的回调处理。
 */
class TestRdbUpgradeCallback : public NativeRdb::RdbOpenCallback {
public:
    /**
     * @brief 数据库创建时的回调函数
     * @param rdbStore 数据库存储对象引用
     * @return 成功返回NativeRdb::E_OK
     */
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    /**
     * @brief 数据库升级时的回调函数
     * @param rdbStore 数据库存储对象引用
     * @param oldVersion 旧版本号
     * @param newVersion 新版本号
     * @return 成功返回NativeRdb::E_OK
     */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
};

/**
 * @brief 将测试结果写入文件
 * 
 * 该函数将Schema对比结果和任务配置检查结果写入指定的结果文件。
 * 
 * @param result 测试结果结构体，包含所有需要写入的测试结果信息
 */
void WriteTestResultToFile(const TestResult &result);

} // namespace OHOS::Media
#endif // MEDIA_LIBRARY_UPGRADE_SCHEMA_TEST_H