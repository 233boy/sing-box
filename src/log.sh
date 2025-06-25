is_log_level_list=(
    trace
    debug
    info
    warn
    error
    fatal
    panic
    none
    del
)
log_set() {
    if [[ $1 ]]; then
        for v in ${is_log_level_list[@]}; do
            [[ $(grep -E -i "^${1,,}$" <<<$v) ]] && is_log_level_use=$v && break
        done
        [[ ! $is_log_level_use ]] && {
            err "无法识别 log 参数: $@ \n请使用 $is_core log [${is_log_level_list[@]}] 进行相关设定.\n备注: del 参数仅临时删除 log 文件; none 参数将不会生成 log 文件."
        }
        case $is_log_level_use in
        del)
            rm -rf $is_log_dir/*.log
            msg "\n $(_green 已临时删除 log 文件, 如果你想要完全禁止生成 log 文件请使用: $is_core log none)\n"
            ;;
        none)
            rm -rf $is_log_dir/*.log
            cat <<<$(jq '.log={"disabled":true}' $is_config_json) >$is_config_json
            ;;
        *)
            cat <<<$(jq '.log={output:"/var/log/'$is_core'/access.log",level:"'$is_log_level_use'","timestamp":true}' $is_config_json) >$is_config_json
            ;;
        esac

        manage restart &
        [[ $1 != 'del' ]] && msg "\n已更新 Log 设定为: $(_green $is_log_level_use)\n"
    else
        if [[ -f $is_log_dir/access.log ]]; then
            msg "\n 提醒: 按 $(_green Ctrl + C) 退出\n"
            tail -f $is_log_dir/access.log
        else
            err "无法找到 log 文件."
        fi
    fi
}