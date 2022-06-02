import Extension from '@ohos.application.DataShareExtensionAbility'

import dataAbility from '@ohos.data.dataAbility';
import rdb from '@ohos.data.rdb';

let DB_NAME = "DB00.db";
let TBL_NAME = "TBL00";
let DDL_TBL_CREATE = "CREATE TABLE IF NOT EXISTS "
+ TBL_NAME
+ " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER)";

let rdbStore;

export default class DataShareExtAbility extends Extension {
    private rdbStore_;

    onCreate(want) {
        console.log('[ttt] [DataShareTest] <<Provider>> DataShareExtAbility onCreate, want:' + want.abilityName);
        console.log('[ttt] [DataShareTest] <<Provider>> this.context:' + this.context);
        rdb.getRdbStore(this.context, { name: DB_NAME }, 1, function(err, data) {
            console.log('[ttt] [DataShareTest] <<Provider>> DataShareExtAbility onCreate, getRdbStore done err:' + JSON.stringify(err));
            rdbStore = data;
            rdbStore.executeSql(DDL_TBL_CREATE, [], function(err) {
                console.log('[ttt] [DataShareTest] <<Provider>> DataShareExtAbility onCreate, executeSql done err:' + JSON.stringify(err));
            });
        });
    }

    getFileTypes(uri: string, mimeTypeFilter: string) {
        console.info('[ttt] [DataShareTest] <<Provider>> [getFileTypes] enter');
        let ret = new Array("type01", "type02", "type03");
        console.info('[ttt] [DataShareTest] <<Provider>> [getFileTypes] leave, ret:' + ret);
        return ret;
    }

    insert(uri, value, callback) {
        console.info('[ttt] [DataShareTest] <<Provider>> [insert] enter');
        if (value == null) {
            console.info('[ttt] [DataShareTest] <<Provider>> [insert] invalid valueBuckets');
            return;
        }
        rdbStore.insert(TBL_NAME, value, function(err, ret) {
            console.info('[ttt] [DataShareTest] <<Provider>> [insert] callback ret:' + ret);
            if (callback != undefined) {
                callback(err, ret);
            }
        });
        console.info('[ttt] [DataShareTest] <<Provider>> [insert] leave');
    }

    update(uri, value, predicates, callback) {
        console.info('[ttt] [DataShareTest] <<Provider>> [update] enter');
        if (predicates == null || predicates == undefined) {
            console.info('[ttt] [DataShareTest] <<Provider>> [update] invalid predicates');
            return;
        }
        let rdbPredicates = dataAbility.createRdbPredicates(TBL_NAME, predicates);
        rdbStore.update(value, rdbPredicates, function(err, ret) {
            console.info('[ttt] [DataShareTest] <<Provider>> [update] callback ret:' + ret);
            if (callback != undefined) {
                callback(err, ret);
            }
        });
        console.info('[ttt] [DataShareTest] <<Provider>> [update] leave');
    }

    delete(uri, predicates, callback) {
        console.info('[ttt] [DataShareTest] <<Provider>> [delete] enter');
        if (predicates == null || predicates == undefined) {
            console.info('[ttt] [DataShareTest] <<Provider>> [delete] invalid predicates');
            return;
        }
        let rdbPredicates = dataAbility.createRdbPredicates(TBL_NAME, predicates);
        rdbStore.delete(rdbPredicates, function(err, ret) {
            console.info('[ttt] [DataShareTest] <<Provider>> [delete] ret:' + ret);
            if (callback != undefined) {
                callback(err, ret);
            }
        });
        console.info('[ttt] [DataShareTest] <<Provider>> [delete] leave');
    }

    query(uri, columns, predicates, callback) {
        console.info('[ttt] [DataShareTest] <<Provider>> [query] enter');
        if (predicates == null || predicates == undefined) {
            console.info('[ttt] [DataShareTest] <<Provider>> [query] invalid predicates');
        }
        let rdbPredicates = dataAbility.createRdbPredicates(TBL_NAME, predicates);
        rdbStore.query(rdbPredicates, columns, function(err, resultSet) {
            console.info('[ttt] [DataShareTest] <<Provider>> [query] ret: ' + resultSet);
            if (resultSet != undefined) {
                console.info('[ttt] [DataShareTest] <<Provider>> [query] resultSet.rowCount: ' + resultSet.rowCount);
            }
            if (callback != undefined) {
                callback(err, resultSet);
            }
        });
        console.info('[ttt] [DataShareTest] <<Provider>> [query] leave');
    }

    getType(uri: string) {
        console.info('[ttt] [DataShareTest] <<Provider>> [getType] enter');
        let ret = "image";
        console.info('[ttt] [DataShareTest] <<Provider>> [getType] leave, ret:' + ret);
        return ret;
    }

    batchInsert(uri: string, valueBuckets, callback) {
        console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] enter');
        if (valueBuckets == null || valueBuckets.length == undefined) {
            console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] invalid valueBuckets');
            return;
        }
        console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] valueBuckets.length:' + valueBuckets.length);
        valueBuckets.forEach(vb => {
            console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] vb:' + JSON.stringify(vb));
            rdbStore.insert(TBL_NAME, vb, function(err, ret) {
                console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] callback ret:' + ret);
                if (callback != undefined) {
                    callback(err, ret);
                }
            });
        });
        console.info('[ttt] [DataShareTest] <<Provider>> [batchInsert] leave');
    }

    normalizeUri(uri: string) {
        console.info('[ttt] [DataShareTest] <<Provider>> [normalizeUri] enter');
        let ret = "normalize+" + uri;
        console.info('[ttt] [DataShareTest] <<Provider>> [normalizeUri] leave, ret:' + ret);
        return ret;
    }

    denormalizeUri(uri: string) {
        console.info('[ttt] [DataShareTest] <<Provider>> [denormalizeUri] enter');
        let ret = "denormalize+" + uri;
        console.info('[ttt] [DataShareTest] <<Provider>> [denormalizeUri] leave, ret:' + ret);
        return ret;
    }
};