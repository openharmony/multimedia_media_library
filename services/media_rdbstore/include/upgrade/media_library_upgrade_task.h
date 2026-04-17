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

#ifndef MEDIA_LIBRARY_UPGRADE_TASK_H
#define MEDIA_LIBRARY_UPGRADE_TASK_H

#include "rdb_store.h"
#include "upgrade_visibility.h"
#include <string>
#include <memory>
#include <functional>

namespace OHOS {
namespace Media {

/**
 * @brief 升级任务接口（策略模式）
 *
 * 定义升级任务的接口
 */
class IUpgradeTask {
public:
    virtual ~IUpgradeTask() = default;

    /**
     * @brief 执行升级任务
     * @param store 数据库存储对象
     * @return 错误码，E_OK 表示成功
     */
    virtual int32_t Execute(NativeRdb::RdbStore& store) = 0;

    /**
     * @brief 获取版本号
     * @return 版本号
     */
    virtual int32_t GetVersion() const = 0;

    /**
     * @brief 获取任务名称
     * @return 任务名称
     */
    virtual std::string GetName() const = 0;

    /**
     * @brief 获取模块名称
     * @return 模块名称
     */
    virtual std::string GetModuleName() const = 0;

    /**
     * @brief 是否为同步升级任务
     * @return true 表示同步任务，false 表示异步任务
     */
    virtual bool IsSync() const = 0;
};

/**
 * @brief 升级任务类（使用函数指针）
 *
 * 统一的升级任务类，通过函数指针（std::function）封装不同的升级逻辑
 * 避免为每个版本号创建单独的类
 */
class UpgradeTask : public IUpgradeTask {
public:
    /**
     * @brief 升级函数类型定义
     */
    using UpgradeFunc = std::function<int32_t(NativeRdb::RdbStore&)>;

    /**
     * @brief 升级任务配置
     */
    struct Config {
        int32_t version;         // 版本号
        std::string name;        // 任务名称
        std::string moduleName;  // 模块名称
        bool isSync;             // 是否为同步任务
        UpgradeFunc upgradeFunc; // 升级函数

        Config(int32_t ver, const std::string& nm, const std::string& mod, bool sync, UpgradeFunc func)
            : version(ver), name(nm), moduleName(mod), isSync(sync), upgradeFunc(func) {}
    };

    /**
     * @brief 构造函数
     * @param config 升级任务配置
     */
    explicit UpgradeTask(const Config& config)
        : version_(config.version), name_(config.name), moduleName_(config.moduleName),
          isSync_(config.isSync), upgradeFunc_(config.upgradeFunc) {}

    ~UpgradeTask() override = default;

    /**
     * @brief 执行升级任务（调用函数指针）
     * @param store 数据库存储对象
     * @return 错误码
     */
    int32_t Execute(NativeRdb::RdbStore& store) override;

    int32_t GetVersion() const override { return version_; }
    std::string GetName() const override { return name_; }
    std::string GetModuleName() const override { return moduleName_; }
    bool IsSync() const override { return isSync_; }

private:
    int32_t version_;
    std::string name_;
    std::string moduleName_;
    bool isSync_;
    UpgradeFunc upgradeFunc_;
};

class UpgradeModuleTask : public IUpgradeTask {
public:
    /**
     * @brief 升级函数类型定义
     */
    using UpgradeModuleFunc = std::function<std::vector<std::pair<int32_t, int32_t>>(NativeRdb::RdbStore&)>;

    /**
     * @brief 升级任务配置
     */
    struct Config {
        int32_t version;
        std::string name;
        std::string moduleName;
        bool isSync;
        UpgradeModuleFunc upgradeFunc;

        Config(int32_t ver, const std::string& nm, const std::string& mod, bool sync, UpgradeModuleFunc func)
            : version(ver), name(nm), moduleName(mod), isSync(sync), upgradeFunc(func) {}
    };

    /**
     * @brief 构造函数
     * @param config 升级任务配置
     */
    explicit UpgradeModuleTask(const Config& config)
        : version_(config.version), name_(config.name), moduleName_(config.moduleName),
          isSync_(config.isSync), upgradeFunc_(config.upgradeFunc) {}

    ~UpgradeModuleTask() override = default;

    /**
     * @brief 执行升级任务（调用函数指针）
     * @param store 数据库存储对象
     * @return 错误码
     */
    int32_t Execute(NativeRdb::RdbStore& store) override;

    int32_t GetVersion() const override { return version_; }
    std::string GetName() const override { return name_; }
    std::string GetModuleName() const override { return moduleName_; }
    bool IsSync() const override { return isSync_; }

private:
    int32_t version_;
    std::string name_;
    std::string moduleName_;
    bool isSync_;
    UpgradeModuleFunc upgradeFunc_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_TASK_H