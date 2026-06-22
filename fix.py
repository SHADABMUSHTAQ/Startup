with open('app/workers/siem_worker.py', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if line.strip() == "if alert_ops:":
        lines = lines[:i+1]
        break

lines.extend([
    "                            await db.security_alerts.bulk_write(alert_ops, ordered=False)\n",
    "\n",
    "                    except Exception as e:\n",
    "                        logger.error(f\"[SIEM][DB] dual-write failed: {e}\")\n",
    "                        ack_ids = []\n",
    "\n",
    "                    if ack_ids:\n",
    "                        for _, alert_doc, log_message in pending_alert_docs:\n",
    "                            try:\n",
    "                                await redis.publish(\"security_alerts\", json_dumps(alert_doc))\n",
    "                            except Exception as e:\n",
    "                                logger.error(f\"[SIEM][REDIS] alert publish failed: {e}\")\n",
    "                            else:\n",
    "                                logger.info(log_message)\n",
    "\n",
    "                    # Batch Acknowledge\n",
    "                    if ack_ids:\n",
    "                        async with redis.pipeline(transaction=True) as pipe:\n",
    "                            for mid in ack_ids:\n",
    "                                await pipe.xack(RAW_LOGS_QUEUE, SIEM_GROUP, mid)\n",
    "                            await pipe.execute()\n",
    "\n",
    "            except Exception as e:\n",
    "                error_msg = str(e)\n",
    "                if \"NOGROUP\" in error_msg:\n",
    "                    # Self-Healing Pipeline: If db was flushed, automatically rebuild the stream\n",
    "                    try:\n",
    "                        await redis.xgroup_create(RAW_LOGS_QUEUE, SIEM_GROUP, mkstream=True)\n",
    "                        logger.info(\"[SIEM-CORE] Auto-Healed NOGROUP missing stream.\")\n",
    "                    except Exception:\n",
    "                        pass\n",
    "                else:\n",
    "                    logger.error(f\"[SIEM-CORE] Pipeline Crash: {e}\")\n",
    "                await asyncio.sleep(1)\n",
    "    finally:\n",
    "        try:\n",
    "            await redis.close()\n",
    "        except Exception:\n",
    "            pass\n",
    "        try:\n",
    "            client.close()\n",
    "        except Exception:\n",
    "            pass\n",
    "\n",
    "if __name__ == \"__main__\":\n",
    "    try:\n",
    "        asyncio.run(siem_worker())\n",
    "    except KeyboardInterrupt:\n",
    "        logger.info(\"WarSOC SIEM offline.\")\n"
])

with open('app/workers/siem_worker.py', 'w') as f:
    f.writelines(lines)
