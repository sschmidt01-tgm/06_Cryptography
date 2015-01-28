package cryptpgraphy;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class for logging things
 * @author Dominik Scholz
 * @version 0.1
 */
public class Log {

    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    private static Logger logger = LogManager.getLogger();

    /**
     * Logs a message with debug priority
     * @param message the message to be logged
     */
    public static void debug(String message) {
        logger.debug(message);
    }

    /**
     * Logs a message with error priority
     * @param message the message to be logged
     */
    public static void error(String message) {
        logger.error(message);
    }

    /**
     * Logs a message with info priority
     * @param message the message to be logged
     */
    public static void info(String message) {
        logger.info(message);
    }

    /**
     * Logs a message with warn priority
     * @param message the message to be logged
     */
    public static void warn(String message) {
        logger.warn(message);
    }
}