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

#ifndef MEDIA_LIBRARY_UPGRADE_MANAGER_H
#define MEDIA_LIBRARY_UPGRADE_MANAGER_H

#include "media_library_upgrade_executor.h"
#include "media_library_upgrade_observer.h"
#include "rdb_store.h"
#include "medialibrary_db_const.h"
#include <memory>

namespace OHOS {
namespace Media {
#ifndef EXPORT
#define EXPORT __attribute__ ((visibility ("default")))
#endif

struct UpgradeManagerConfig {
    bool isCloned;
    std::string upgradeEventPath;
    std::string rdbConfigPath;
    int32_t currentVersion {MEDIA_RDB_VERSION};
    int32_t targetVersion {MEDIA_RDB_VERSION};
    UpgradeManagerConfig(bool isCloned_, std::string upgradeEventPath_, std::string rdbConfigPath_,
    int32_t currentVersion_, int32_t targetVersion_) : isCloned(isCloned_), upgradeEventPath(upgradeEventPath_),
        rdbConfigPath(rdbConfigPath_), currentVersion(currentVersion_), targetVersion(targetVersion_) {}
};

/**
 * @brief 升级管理器
 *
 * 提供统一的升级管理接口
 */
class EXPORT UpgradeManager {
public:
    /**
     * @brief 获取管理器单例
     * @return 管理器引用
     */
    static UpgradeManager& GetInstance();

    UpgradeManager(const UpgradeManager&) = delete;
    UpgradeManager& operator=(const UpgradeManager&) = delete;

    /**
     * @brief 初始化升级管理器
     * @return 错误码
     */
    int32_t Initialize(const UpgradeManagerConfig& config);

    /**
     * @brief 同步升级
     * @param store 数据库存储对象
     * @return 错误码
     */
    int32_t UpgradeSync(NativeRdb::RdbStore& store);

    /**
     * @brief 异步升级
     * @param store 数据库存储对象
     * @return 错误码
     */
    int32_t UpgradeAsync(NativeRdb::RdbStore& store);

    /**
     * @brief 设置观察者
     * @param observer 观察者指针
     */
    void SetObserver(std::shared_ptr<IUpgradeObserver> observer);

private:
    UpgradeManager() = default;
    ~UpgradeManager() = default;

    /**
     * @brief 执行升级
     * @param store 数据库存储对象
     * @param isSync 是否同步升级
     * @return 错误码
     */
    int32_t DoUpgrade(NativeRdb::RdbStore& store, bool isSync);

    UpgradeExecutor executor_;
    std::shared_ptr<IUpgradeObserver> observer_;
    bool isCloned_ {false};
    int32_t currentVersion_ {MEDIA_RDB_VERSION};
    int32_t targetVersion_ {MEDIA_RDB_VERSION};
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_MANAGER_H