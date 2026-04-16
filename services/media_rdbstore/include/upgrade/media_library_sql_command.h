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

#ifndef MEDIA_LIBRARY_SQL_COMMAND_H
#define MEDIA_LIBRARY_SQL_COMMAND_H

#include "upgrade_visibility.h"
#include "rdb_store.h"
#include "value_object.h"
#include <string>
#include <memory>
#include <vector>
#include <sstream>

namespace OHOS {
namespace Media {

/**
 * @brief SQL命令接口
 *
 * 将 SQL 操作封装为命令对象，使用占位符+参数化查询方式执行 SQL
 */
class ISqlCommand {
public:
    virtual ~ISqlCommand() = default;

    /**
     * @brief 执行 SQL 命令（使用占位符+参数化查询）
     * @param store 数据库存储对象
     * @return 错误码
     */
    virtual int32_t Execute(NativeRdb::RdbStore& store) = 0;

    /**
     * @brief 获取 SQL 语句（包含占位符）
     * @return SQL 语句字符串
     */
    virtual std::string GetSql() const = 0;

    /**
     * @brief 获取 SQL 参数
     * @return 参数列表
     */
    virtual std::vector<NativeRdb::ValueObject> GetArgs() const = 0;
};

/**
 * @brief 原始 SQL 命令（无参数）
 */
class RawSqlCommand : public ISqlCommand {
public:
    explicit RawSqlCommand(const std::string& sql) : sql_(sql) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override { return sql_; }
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string sql_;
};

/**
 * @brief 参数化 SQL 命令（支持占位符和参数）
 */
class ParameterizedSqlCommand : public ISqlCommand {
public:
    ParameterizedSqlCommand(const std::string& sql, const std::vector<NativeRdb::ValueObject>& args)
        : sql_(sql), args_(args) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override { return sql_; }
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return args_; }

private:
    std::string sql_;
    std::vector<NativeRdb::ValueObject> args_;
};

/**
 * @brief 添加列命令
 */
class AddColumnCommand : public ISqlCommand {
public:
    AddColumnCommand(const std::string& tableName,
                     const std::string& columnName,
                     const std::string& columnType)
        : tableName_(tableName), columnName_(columnName), columnType_(columnType) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string tableName_;
    std::string columnName_;
    std::string columnType_;
};

/**
 * @brief 删除列命令
 */
class DropColumnCommand : public ISqlCommand {
public:
    DropColumnCommand(const std::string& tableName, const std::string& columnName)
        : tableName_(tableName), columnName_(columnName) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string tableName_;
    std::string columnName_;
};

/**
 * @brief 创建索引命令
 */
class CreateIndexCommand : public ISqlCommand {
public:
    CreateIndexCommand(const std::string& indexName,
                       const std::string& tableName,
                       const std::string& columnName)
        : indexName_(indexName), tableName_(tableName), columnName_(columnName) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string indexName_;
    std::string tableName_;
    std::string columnName_;
};

/**
 * @brief 删除索引命令
 */
class DropIndexCommand : public ISqlCommand {
public:
    explicit DropIndexCommand(const std::string& indexName) : indexName_(indexName) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string indexName_;
};

/**
 * @brief 删除触发器命令
 */
class DropTriggerCommand : public ISqlCommand {
public:
    explicit DropTriggerCommand(const std::string& triggerName) : triggerName_(triggerName) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string triggerName_;
};

/**
 * @brief 删除表命令
 */
class DropTableCommand : public ISqlCommand {
public:
    explicit DropTableCommand(const std::string& tableName) : tableName_(tableName) {}

    int32_t Execute(NativeRdb::RdbStore& store) override;
    std::string GetSql() const override;
    std::vector<NativeRdb::ValueObject> GetArgs() const override { return {}; }

private:
    std::string tableName_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_SQL_COMMAND_H