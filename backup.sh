for dir in config persistent; do
    rsync -auv /home/haraken/$dir/ /data/backup/$dir/
    rsync -auv /var/lib/mysql/ /data/backup/mysql/
done
